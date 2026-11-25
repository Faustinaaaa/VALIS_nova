use crate::myers::Edit;
use ff::Field;
use nova_snark::{
    frontend::{num::AllocatedNum, ConstraintSystem, SynthesisError},
    provider::{PallasEngine, VestaEngine},
    traits::{circuit::StepCircuit, Engine},
};

use crate::gadgets::{enforce_byte, enforce_source_bound, equal_if, selectors, sum};

// Pallas/Vesta 构成 Nova 使用的曲线循环；业务电路在 E1 的标量域 F 上计算。
pub(crate) type E1 = PallasEngine;
pub(crate) type E2 = VestaEngine;
pub(crate) type F = <E1 as Engine>::Scalar;
pub(crate) type Num = AllocatedNum<F>;
// 所有长度和游标均按原始字节计数，允许非 UTF-8 文件。
pub(crate) const BLOCK: usize = 32;
// 每个操作块固定编码为 34 个域元素：[操作类型, 有效长度, 32 个插入字节槽位]。
const ROW: usize = 2 + BLOCK;

pub(crate) fn scalar(n: usize) -> F {
    F::from(n as u64)
}

/// 在电路外拆分 Myers 操作：每块最多 BLOCK 个字节，且不混合操作类型。
pub(crate) fn chunks(edits: &[Edit]) -> Vec<Edit> {
    let mut result = Vec::new();
    for edit in edits {
        match edit {
            Edit::Keep(n) | Edit::Delete(n) => {
                let mut remaining = *n;
                while remaining > 0 {
                    let count = remaining.min(BLOCK);
                    result.push(if matches!(edit, Edit::Keep(_)) {
                        Edit::Keep(count)
                    } else {
                        Edit::Delete(count)
                    });
                    remaining -= count;
                }
            }
            Edit::Insert(text) => {
                for part in text.chunks(BLOCK) {
                    result.push(Edit::Insert(part.to_vec()));
                }
            }
        }
    }
    // Nova 至少需要一步；两个空文件用 keep(0) 表示不消费任何字节的空步骤。
    if result.is_empty() {
        result.push(Edit::Keep(0));
    }
    result
}

/// 在 BLOCK 和约束逻辑固定时，形状由两份文本长度及操作块数决定。
/// 状态：[三个游标, 原文长度, 新文承诺, 新文链, 脚本承诺, 脚本链, 原文承诺, 原文链]。
/// 原文只分配为私有 witness，不进入递归输入/输出或最终公开证明状态。
/// 末尾追加目标承诺和动态哈希链；消费的原文字节绑定到公开承诺。
#[derive(Clone, Debug)]
pub(crate) struct EditCircuit {
    pub(crate) old_len: usize,
    pub(crate) new_len: usize,
    pub(crate) steps: usize,
    // 仅保存本步原文片段，未使用槽填零，不保存整份原文。
    source_block: [F; BLOCK],
    // 当前新文片段；全文只由电路外程序读取，不进入递归状态。
    target_block: [F; BLOCK],
    // 私有盐只在首步初始化链时使用，不进入公开状态。
    salt: F,
    operation_block: [F; ROW],
}

pub(crate) fn encode_edit(edit: &Edit) -> [F; ROW] {
    let mut row = [F::ZERO; ROW];
    match edit {
        Edit::Keep(n) => row[1] = scalar(*n),
        Edit::Delete(n) => {
            row[0] = F::ONE;
            row[1] = scalar(*n);
        }
        Edit::Insert(text) => {
            let chars = text;
            assert!(chars.len() <= BLOCK);
            row[0] = scalar(2);
            row[1] = scalar(chars.len());
            for (i, ch) in chars.iter().enumerate() {
                row[i + 2] = F::from(*ch as u64);
            }
        }
    }
    row
}

impl EditCircuit {
    /// 在电路外构造公开初始状态 z0，同时确定本次证明的电路形状。
    pub(crate) fn statement(
        old_len: usize,
        new: &[u8],
        tape: &[Edit],
        commitment: F,
    ) -> (Self, Vec<F>) {
        let circuit = Self {
            old_len,
            new_len: new.len(),
            steps: tape.len(),
            source_block: [F::ZERO; BLOCK],
            target_block: [F::ZERO; BLOCK],
            salt: F::ZERO,
            operation_block: [F::ZERO; ROW],
        };
        // 三个游标从 0 开始；仅原文长度公开，原文字节不会写入 z0。
        let mut state = vec![F::ZERO; 3];
        state.push(scalar(old_len));
        state.push(crate::hashchain::target_commitment(new));
        state.push(F::ZERO);
        state.push(crate::hashchain::script_commitment(tape));
        state.push(F::ZERO);
        state.push(commitment);
        state.push(F::ZERO);
        (circuit, state)
    }

    /// 每步只装入当前操作；脚本链负责绑定公开脚本及顺序。
    pub(crate) fn set_edit_step(&mut self, edit: &Edit) {
        self.operation_block = encode_edit(edit);
    }

    pub(crate) fn set_salt(&mut self, salt: F) {
        self.salt = salt;
    }

    /// 依次装入本步消费的新文字节，返回下一步偏移。delete 不消费新文。
    pub(crate) fn set_target_step(
        &mut self,
        after: &[u8],
        offset: usize,
        edit: &Edit,
    ) -> Result<usize, String> {
        if after.len() != self.new_len {
            return Err("target length mismatch".into());
        }
        let count = match edit {
            Edit::Keep(n) => *n,
            Edit::Insert(bytes) => bytes.len(),
            Edit::Delete(_) => 0,
        };
        if count > BLOCK {
            return Err("target block exceeds capacity".into());
        }
        let end = offset.checked_add(count).ok_or("target offset overflow")?;
        self.target_block.fill(F::ZERO);
        for slot in 0..count {
            self.target_block[slot] =
                F::from(after.get(offset + slot).copied().unwrap_or(0) as u64);
        }
        Ok(end)
    }

    /// 电路外为当前步骤准备原文片段，返回下一步的原文偏移。
    /// 只检查输入尺寸；脚本越界时填零，让电路的长度约束拒绝。
    pub(crate) fn set_source_step(
        &mut self,
        before: &[u8],
        offset: usize,
        edit: &Edit,
    ) -> Result<usize, String> {
        if before.len() != self.old_len {
            return Err("private source length mismatch".into());
        }
        let count = match edit {
            Edit::Keep(n) | Edit::Delete(n) => *n,
            Edit::Insert(_) => 0,
        };
        if count > BLOCK {
            return Err("source block exceeds capacity".into());
        }
        let end = offset.checked_add(count).ok_or("source offset overflow")?;
        self.source_block.fill(F::ZERO);
        for slot in 0..count {
            self.source_block[slot] =
                F::from(before.get(offset + slot).copied().unwrap_or(0) as u64);
        }
        Ok(end)
    }

    /// 验证端在证明验证通过后必须执行的终态检查（不是 synthesize 内的约束）。
    /// 防止只证明一个合法前缀：两份文本和操作序列都必须被完整消费。
    pub(crate) fn completed(&self, initial: &[F], output: &[F]) -> bool {
        initial.len() == self.arity()
            && output.len() == initial.len()
            && output[0] == scalar(self.old_len)
            && output[1] == scalar(self.new_len)
            && output[2] == scalar(self.steps)
            && initial[initial.len() - 1] == F::ZERO
            && initial[5] == F::ZERO
            && output[3..5] == initial[3..5]
            && initial[7] == F::ZERO
            && output[6] == initial[6]
            && output[8] == initial[8]
            && crate::hashchain::script_finish(output[7], self.steps) == initial[6]
            && crate::hashchain::target_finish(output[5], self.new_len) == initial[4]
            && crate::hashchain::finish(output[output.len() - 1], self.old_len)
                == initial[initial.len() - 2]
    }
}

impl StepCircuit<F> for EditCircuit {
    /// 新文全文不再进入状态，只有三个承诺、三条链和游标。
    fn arity(&self) -> usize {
        10
    }

    /// 为一个编辑块生成 R1CS 约束；不能根据本步操作类型减少或增加约束。
    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[Num],
    ) -> Result<Vec<Num>, SynthesisError> {
        // 只分配当前片段的固定 BLOCK 个私有字节，不再分配整份原文。
        let old = self
            .source_block
            .iter()
            .enumerate()
            .map(|(i, ch)| Num::alloc(cs.namespace(|| format!("private source {i}")), || Ok(*ch)))
            .collect::<Result<Vec<_>, _>>()?;
        // 私有字节必须在 0..=255；不能只依赖 Rust 的 u8 类型限制 witness。
        for (i, byte) in old.iter().enumerate() {
            enforce_byte(cs.namespace(|| format!("source byte range {i}")), byte)?;
        }
        // 将公开原文长度绑定到 setup 使用的长度。
        cs.enforce(
            || "source length matches shape",
            |lc| lc + z[3].get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + (scalar(self.old_len), CS::one()),
        );
        let new = self
            .target_block
            .iter()
            .enumerate()
            .map(|(i, byte)| {
                Num::alloc(cs.namespace(|| format!("target fragment {i}")), || {
                    Ok(*byte)
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut target_chain = z[5].clone();
        let mut chain = z[z.len() - 1].clone();
        for (i, byte) in new.iter().enumerate() {
            enforce_byte(cs.namespace(|| format!("target byte range {i}")), byte)?;
        }
        // 当前操作作为 witness 输入，脚本哈希链绑定其内容及执行顺序。
        let one = sum(cs.namespace(|| "constant one"), &[], 1)?;
        // first 精确表示操作游标是否为零，用来初始化私有盐。
        let first = Num::alloc(cs.namespace(|| "first step"), || {
            Ok(
                if z[2].get_value().ok_or(SynthesisError::AssignmentMissing)? == F::ZERO {
                    F::ONE
                } else {
                    F::ZERO
                },
            )
        })?;
        let inverse = Num::alloc(cs.namespace(|| "cursor inverse"), || {
            Ok(Option::<F>::from(
                z[2].get_value()
                    .ok_or(SynthesisError::AssignmentMissing)?
                    .invert(),
            )
            .unwrap_or(F::ZERO))
        })?;
        cs.enforce(
            || "first zero",
            |lc| lc + z[2].get_variable(),
            |lc| lc + first.get_variable(),
            |lc| lc,
        );
        cs.enforce(
            || "first nonzero",
            |lc| lc + z[2].get_variable(),
            |lc| lc + inverse.get_variable(),
            |lc| lc + CS::one() - first.get_variable(),
        );
        let salt = Num::alloc(cs.namespace(|| "private salt"), || Ok(self.salt))?;
        chain = crate::hashchain::initialize_if(
            cs.namespace(|| "salted initialization"),
            &chain,
            &salt,
            &first,
        )?;
        let row = self
            .operation_block
            .iter()
            .enumerate()
            .map(|(i, value)| {
                Num::alloc(cs.namespace(|| format!("operation witness {i}")), || {
                    Ok(*value)
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let script_chain = crate::hashchain::script_absorb(
            cs.namespace(|| "script hashchain"),
            &z[7],
            &row,
            &one,
        )?;
        for slot in 0..BLOCK {
            enforce_byte(
                cs.namespace(|| format!("payload byte range {slot}")),
                &row[2 + slot],
            )?;
        }
        // kinds 为类型的独热编码，约束操作类型只能是 0、1、2。
        let kinds = selectors(cs.namespace(|| "operation kind"), &row[0], &one, 3)?;
        // lengths 为长度的独热编码，约束有效长度只能是 0..=BLOCK。
        let lengths = selectors(cs.namespace(|| "block length"), &row[1], &one, BLOCK + 1)?;
        // keep/delete 消费原文；keep/insert 消费新文。
        let reads_old = sum(cs.namespace(|| "keep or delete"), &kinds[..2], 0)?;
        let reads_new = sum(
            cs.namespace(|| "keep or insert"),
            &[kinds[0].clone(), kinds[2].clone()],
            0,
        )?;

        let mut old_increments = vec![z[0].clone()];
        let mut new_increments = vec![z[1].clone()];
        // 始终生成全部 32 个槽位的约束；未启用的槽位仍存在，保证步骤形状一致。
        for slot in 0..BLOCK {
            let mut slot_cs = cs.namespace(|| format!("slot {slot}"));
            // active = sum(lengths[slot+1..])，等价于“有效长度 > 当前槽位编号”。
            // 例如长度为 2 时，32 个槽位中前两个 active 为 1，其余 30 个为 0。
            let active = sum(slot_cs.namespace(|| "active"), &lengths[slot + 1..], 0)?;
            let old_enabled = active.mul(slot_cs.namespace(|| "old enabled"), &reads_old)?;
            let new_enabled = active.mul(slot_cs.namespace(|| "new enabled"), &reads_new)?;
            let old_char = old[slot].clone();
            let new_char = new[slot].clone();
            let keep = active.mul(slot_cs.namespace(|| "keep enabled"), &kinds[0])?;
            let insert = active.mul(slot_cs.namespace(|| "insert enabled"), &kinds[2])?;
            // keep：本槽启用时，约束原文字节等于新文字节。
            equal_if(
                slot_cs.namespace(|| "keep content"),
                &keep,
                &old_char,
                &new_char,
            );
            // insert：本槽启用时，新文字节必须等于操作行指定的插入字节。
            // delete 无需字节相等检查，只需合法读取原文并推进原文游标。
            equal_if(
                slot_cs.namespace(|| "insert content"),
                &insert,
                &new_char,
                &row[2 + slot],
            );
            // keep 和 delete 消费的字节进入链，insert 和填充槽保持链不变。
            chain = crate::hashchain::absorb_if(
                slot_cs.namespace(|| "source hashchain"),
                &chain,
                &old_char,
                &old_enabled,
            )?;
            old_increments.push(old_enabled);
            target_chain = crate::hashchain::target_absorb_if(
                slot_cs.namespace(|| "target hashchain"),
                &target_chain,
                &new_char,
                &new_enabled,
            )?;
            new_increments.push(new_enabled);
        }
        // 累加实际启用的读操作：填充槽位不会推进文本游标。
        // 每次都消费一个编辑块，因此操作游标固定加 1（keep(0) 也如此）。
        let mut next = z.to_vec();
        next[0] = sum(cs.namespace(|| "advance old cursor"), &old_increments, 0)?;
        // 剩余长度必须是非负的 64 位整数，因此本步不能越过原文末尾。
        enforce_source_bound(cs.namespace(|| "source bound"), &next[0], self.old_len)?;
        next[1] = sum(cs.namespace(|| "advance new cursor"), &new_increments, 0)?;
        enforce_source_bound(cs.namespace(|| "target bound"), &next[1], self.new_len)?;
        next[2] = sum(cs.namespace(|| "advance edit cursor"), &[z[2].clone()], 1)?;
        // 公开承诺和原文长度保持不变；只更新三个游标和三条链。
        enforce_source_bound(cs.namespace(|| "script bound"), &next[2], self.steps)?;
        next[7] = script_chain;
        let last = next.len() - 1;
        next[last] = chain;
        next[5] = target_chain;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashchain;
    use nova_snark::frontend::util_cs::test_cs::TestConstraintSystem;

    fn step(c: &EditCircuit, state: &[F]) -> (Vec<F>, bool, usize) {
        let mut cs = TestConstraintSystem::<F>::new();
        let z = state
            .iter()
            .enumerate()
            .map(|(i, value)| {
                Num::alloc(cs.namespace(|| format!("input {i}")), || Ok(*value)).unwrap()
            })
            .collect::<Vec<_>>();
        let next = c.synthesize(&mut cs, &z).unwrap();
        (
            next.iter().map(|n| n.get_value().unwrap()).collect(),
            cs.is_satisfied(),
            cs.num_constraints(),
        )
    }
    fn execute(
        source: &[u8],
        target: &[u8],
        edits: &[Edit],
        commitment: F,
        poison_padding: bool,
    ) -> bool {
        let tape = chunks(edits);
        let (mut c, z0) = EditCircuit::statement(source.len(), target, &tape, commitment);
        c.set_salt(F::from(7));
        let mut z = z0.clone();
        let mut offset = 0;
        let mut target_offset = 0;
        for edit in &tape {
            c.set_edit_step(edit);
            let previous = offset;
            let target_previous = target_offset;
            offset = c.set_source_step(source, offset, edit).unwrap();
            target_offset = c.set_target_step(target, target_offset, edit).unwrap();
            if poison_padding {
                for byte in &mut c.source_block[offset - previous..] {
                    *byte = F::from(255);
                }
                for byte in &mut c.target_block[target_offset - target_previous..] {
                    *byte = F::from(255);
                }
            }
            let (next, satisfied, _) = step(&c, &z);
            if !satisfied {
                return false;
            }
            z = next;
        }
        c.completed(&z0, &z)
    }

    #[test]
    fn script_chain_binds_order_padding_and_complete_sequence() {
        let source = b"abc";
        let tape = [Edit::Delete(1), Edit::Delete(2)];
        let (mut c, z0) =
            EditCircuit::statement(3, b"", &tape, hashchain::commitment(source, F::from(7)));
        c.set_salt(F::from(7));
        // 两种脚本都能删除同一原文，但只有公开指定的顺序能被接受。
        for (edits, poison, expected) in [
            (vec![Edit::Delete(1), Edit::Delete(2)], false, true),
            (vec![Edit::Delete(2), Edit::Delete(1)], false, false),
            (vec![Edit::Delete(1), Edit::Delete(2)], true, false),
            (vec![Edit::Delete(1)], false, false),
        ] {
            let mut z = z0.clone();
            let mut offset = 0;
            for edit in &edits {
                c.set_edit_step(edit);
                if poison {
                    c.operation_block[2] = F::ONE;
                }
                offset = c.set_source_step(source, offset, edit).unwrap();
                let (next, ok, _) = step(&c, &z);
                assert!(ok);
                z = next;
            }
            assert_eq!(c.completed(&z0, &z), expected);
        }
        let (a, za) = EditCircuit::statement(3, b"", &tape[..1], F::ZERO);
        let (b, zb) = EditCircuit::statement(3, b"", &vec![Edit::Delete(1); 128], F::ZERO);
        assert_eq!(za.len(), 10);
        assert_eq!(zb.len(), 10);
        assert_eq!(step(&a, &za).2, step(&b, &zb).2);
    }

    #[test]
    fn fragments_cover_boundaries_insert_and_padding() {
        let source: Vec<u8> = (0..65).collect();
        let mut target = vec![255];
        target.extend_from_slice(&source[..33]);
        target.push(254);
        let edits = [
            Edit::Insert(vec![255]),
            Edit::Keep(33),
            Edit::Delete(32),
            Edit::Insert(vec![254]),
        ];
        assert!(execute(
            &source,
            &target,
            &edits,
            hashchain::commitment(&source, F::from(7)),
            true
        ));
        assert!(execute(
            b"",
            b"",
            &[],
            hashchain::commitment(b"", F::from(7)),
            true
        ));
        assert!(execute(
            b"",
            &[0, 255],
            &[Edit::Insert(vec![0, 255])],
            hashchain::commitment(b"", F::from(7)),
            true
        ));
        assert!(execute(
            &source,
            b"",
            &[Edit::Delete(65)],
            hashchain::commitment(&source, F::from(7)),
            false
        ));
    }

    #[test]
    fn wrong_fragment_order_deleted_content_and_lengths_are_rejected() {
        let source: Vec<u8> = (0..64).collect();
        let mut swapped = source[32..].to_vec();
        swapped.extend_from_slice(&source[..32]);
        let expected = hashchain::commitment(&source, F::from(7));
        assert!(!execute(
            &swapped,
            b"",
            &[Edit::Delete(64)],
            expected,
            false
        ));
        let mut changed = source.clone();
        changed[40] ^= 1;
        assert!(!execute(
            &changed,
            b"",
            &[Edit::Delete(64)],
            expected,
            false
        ));
        assert!(!execute(&source, b"", &[Edit::Delete(63)], expected, false));
        assert!(!execute(&source, b"", &[Edit::Delete(65)], expected, false));
        assert!(!execute(
            b"x",
            b"a",
            &[Edit::Keep(1)],
            hashchain::commitment(b"x", F::from(7)),
            false
        ));
        assert!(!execute(
            b"",
            b"a",
            &[Edit::Insert(vec![98])],
            hashchain::commitment(b"", F::from(7)),
            false
        ));
    }

    #[test]
    fn private_salt_is_required_even_for_empty_source() {
        for source in [b"".as_slice(), b"abc".as_slice()] {
            let expected = hashchain::commitment(source, F::from(8));
            assert!(!execute(
                source,
                b"",
                &[Edit::Delete(source.len())],
                expected,
                false
            ));
            assert_ne!(expected, hashchain::commitment(source, F::from(7)));
        }
    }

    #[test]
    fn source_constraint_count_does_not_grow_with_file_size() {
        let tape = [Edit::Delete(1)];
        let (short, z_short) = EditCircuit::statement(32, b"", &tape, F::ZERO);
        let (long, z_long) = EditCircuit::statement(2048, b"", &tape, F::ZERO);
        let (_, short_ok, short_count) = step(&short, &z_short);
        let (_, long_ok, long_count) = step(&long, &z_long);
        assert!(short_ok && long_ok);
        assert_eq!(short_count, long_count);
        println!("source lengths 32 and 2048: {short_count} constraints per step");
    }

    #[test]
    fn target_stream_is_bound_and_checks_length() {
        // 编辑本身合法，但片段拼接出的新文不等于公开目标，必须在终态拒绝。
        let target: Vec<u8> = (0..64).collect();
        let mut swapped = target[32..].to_vec();
        swapped.extend_from_slice(&target[..32]);
        let tape = chunks(&[Edit::Keep(64)]);
        let (mut c, z0) = EditCircuit::statement(
            64,
            &target,
            &tape,
            hashchain::commitment(&swapped, F::from(7)),
        );
        c.set_salt(F::from(7));
        let mut z = z0.clone();
        let mut offset = 0;
        for edit in &tape {
            c.set_edit_step(edit);
            c.set_source_step(&swapped, offset, edit).unwrap();
            offset = c.set_target_step(&swapped, offset, edit).unwrap();
            let (next, ok, _) = step(&c, &z);
            assert!(ok);
            z = next;
        }
        assert!(!c.completed(&z0, &z));
        assert!(!execute(
            b"",
            &[0],
            &[Edit::Insert(vec![0, 0])],
            hashchain::commitment(b"", F::from(7)),
            false
        ));
        assert!(!execute(
            b"",
            &[0, 0],
            &[Edit::Insert(vec![0])],
            hashchain::commitment(b"", F::from(7)),
            false
        ));
    }

    #[test]
    fn target_length_does_not_expand_state_or_constraint_count() {
        let tape = [Edit::Delete(1)];
        let (a, za) = EditCircuit::statement(32, &[0; 32], &tape, F::ZERO);
        let (b, zb) = EditCircuit::statement(32, &[0; 2048], &tape, F::ZERO);
        assert_eq!(a.arity(), b.arity());
        assert_eq!(a.arity(), 10);
        assert_eq!(step(&a, &za).2, step(&b, &zb).2);
    }
}
