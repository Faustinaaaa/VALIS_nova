use crate::myers::Edit;
use ff::Field;
use nova_snark::{
    frontend::{num::AllocatedNum, ConstraintSystem, SynthesisError},
    provider::{PallasEngine, VestaEngine},
    traits::{circuit::StepCircuit, Engine},
};

use crate::gadgets::{enforce_byte, equal_if, select, selectors, sum};

// Pallas/Vesta 构成 Nova 使用的曲线循环；业务电路在 E1 的标量域 F 上计算。
pub(crate) type E1 = PallasEngine;
pub(crate) type E2 = VestaEngine;
pub(crate) type F = <E1 as Engine>::Scalar;
pub(crate) type Num = AllocatedNum<F>;
// 所有长度和游标均按原始字节计数，允许非 UTF-8 文件。
pub(crate) const BLOCK: usize = 8;
// 每个操作块固定编码为 10 个域元素：[操作类型, 有效长度, 8 个插入字节槽位]。
const ROW: usize = 2 + BLOCK;

pub(crate) fn scalar(n: usize) -> F {
    F::from(n as u64)
}

/// 在电路外拆分 Myers 操作：每块最多 BLOCK 个字节，且不混合操作类型。
/// 例如 keep(17) 拆成 keep(8)、keep(8)、keep(1)，末块不增加真实字节。
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
/// 公开状态：[原文游标, 新文游标, 操作游标, 原文长度, 新文字节..., 操作序列...]。
/// 原文只分配为私有 witness，不进入递归输入/输出或最终公开证明状态。
/// 未引入原文承诺：证明存在符合脚本的私有原文，不绑定预先指定的文件。
#[derive(Clone, Debug)]
pub(crate) struct EditCircuit {
    pub(crate) old_len: usize,
    pub(crate) new_len: usize,
    pub(crate) steps: usize,
    // 仅 prover 填入原文；setup 用同长度零值确定形状，不能序列化此字段。
    before: Vec<F>,
}

impl EditCircuit {
    /// 在电路外构造公开初始状态 z0，同时确定本次证明的电路形状。
    pub(crate) fn statement(old_len: usize, new: &[u8], tape: &[Edit]) -> (Self, Vec<F>) {
        let circuit = Self {
            old_len,
            new_len: new.len(),
            steps: tape.len(),
            before: vec![F::ZERO; old_len],
        };
        // 三个游标从 0 开始；仅原文长度公开，原文字节不会写入 z0。
        let mut state = vec![F::ZERO; 3];
        state.push(scalar(old_len));
        state.extend(new.iter().map(|&b| F::from(b as u64)));
        for edit in tape {
            // 操作类型：0=keep，1=delete，2=insert。
            // 所有插入槽位先填零，只有 insert 的有效部分写入字节值。
            // 填充零不代表真实文本中的空字节；是否处理该槽位由有效长度决定。
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
            state.extend(row);
        }
        (circuit, state)
    }

    /// 在 prove 阶段装入私有原文
    pub(crate) fn set_source(&mut self, before: &[u8]) -> Result<(), String> {
        if before.len() != self.old_len {
            return Err("private source length mismatch".into());
        }
        self.before = before.iter().map(|&b| F::from(b as u64)).collect();
        Ok(())
    }

    /// 验证端在证明验证通过后必须执行的终态检查（不是 synthesize 内的约束）。
    /// 防止只证明一个合法前缀：两份文本和操作序列都必须被完整消费。
    pub(crate) fn completed(&self, initial: &[F], output: &[F]) -> bool {
        initial.len() == self.arity()
            && output.len() == initial.len()
            && output[0] == scalar(self.old_len)
            && output[1] == scalar(self.new_len)
            && output[2] == scalar(self.steps)
            && output[3..] == initial[3..]
    }
}

impl StepCircuit<F> for EditCircuit {
    /// 状态维数：3 个游标 + 原文长度 + 新文 + 固定宽度的操作序列。
    fn arity(&self) -> usize {
        4 + self.new_len + ROW * self.steps
    }

    /// 为一个编辑块生成 R1CS 约束；不能根据本步操作类型减少或增加约束。
    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[Num],
    ) -> Result<Vec<Num>, SynthesisError> {
        // 私有 witness 用 alloc 而非公开状态 z 传入；所有步骤消费连续、不重叠的位置。
        let old = self
            .before
            .iter()
            .enumerate()
            .map(|(i, ch)| Num::alloc(cs.namespace(|| format!("private source {i}")), || Ok(*ch)))
            .collect::<Result<Vec<_>, _>>()?;
        // 私有字节必须在 0..=255；不能只依赖 Rust 的 u8 类型限制 witness。
        for (i, byte) in old.iter().enumerate() {
            enforce_byte(cs.namespace(|| format!("source byte range {i}")), byte)?;
        }
        // 将公开原文长度绑定到本次 setup 的形状。
        cs.enforce(
            || "source length matches shape",
            |lc| lc + z[3].get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + (scalar(self.old_len), CS::one()),
        );
        let new_end = 4 + self.new_len;
        let new = &z[4..new_end];
        let tape = &z[new_end..];
        for (i, byte) in new.iter().enumerate() {
            enforce_byte(cs.namespace(|| format!("target byte range {i}")), byte)?;
        }
        let one = sum(cs.namespace(|| "constant one"), &[], 1)?;

        // 用操作游标 z[2] 选择当前行；类型、长度、插入字节均绑定到公开操作序列。
        // 每列都读取同一个行号，不能从不同操作行任意拼接字段。
        let row_bits = selectors(cs.namespace(|| "edit position"), &z[2], &one, self.steps)?;
        let mut row = Vec::new();
        for column in 0..ROW {
            let entries = (0..self.steps)
                .map(|i| tape[i * ROW + column].clone())
                .collect::<Vec<_>>();
            row.push(select(
                cs.namespace(|| format!("edit column {column}")),
                &row_bits,
                &entries,
            )?);
        }
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
        // 始终生成全部 8 个槽位的约束；未启用的槽位仍存在，保证步骤形状一致。
        for slot in 0..BLOCK {
            let mut slot_cs = cs.namespace(|| format!("slot {slot}"));
            // active = sum(lengths[slot+1..])，等价于“有效长度 > 当前槽位编号”。
            // 例如长度为 2 时，8 个槽位的 active 依次为 1,1,0,0,0,0,0,0。
            let active = sum(slot_cs.namespace(|| "active"), &lengths[slot + 1..], 0)?;
            let old_enabled = active.mul(slot_cs.namespace(|| "old enabled"), &reads_old)?;
            let new_enabled = active.mul(slot_cs.namespace(|| "new enabled"), &reads_new)?;
            let old_index = sum(slot_cs.namespace(|| "old index"), &[z[0].clone()], slot)?;
            let new_index = sum(slot_cs.namespace(|| "new index"), &[z[1].clone()], slot)?;
            // 启用的查找必须选中“游标 + 槽位偏移”的有效位置，越界无法满足约束。
            // 未启用的查找选择位全零，不要求该偏移位于文本内，结果也为零。
            let old_bits = selectors(
                slot_cs.namespace(|| "old lookup"),
                &old_index,
                &old_enabled,
                old.len(),
            )?;
            let new_bits = selectors(
                slot_cs.namespace(|| "new lookup"),
                &new_index,
                &new_enabled,
                new.len(),
            )?;
            let old_char = select(slot_cs.namespace(|| "old character"), &old_bits, &old)?;
            let new_char = select(slot_cs.namespace(|| "new character"), &new_bits, new)?;
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
            old_increments.push(old_enabled);
            new_increments.push(new_enabled);
        }
        // 累加实际启用的读操作：填充槽位不会推进文本游标。
        // 每次都消费一个编辑块，因此操作游标固定加 1（keep(0) 也如此）。
        let mut next = z.to_vec();
        next[0] = sum(cs.namespace(|| "advance old cursor"), &old_increments, 0)?;
        next[1] = sum(cs.namespace(|| "advance new cursor"), &new_increments, 0)?;
        next[2] = sum(cs.namespace(|| "advance edit cursor"), &[z[2].clone()], 1)?;
        // 公开的新文、脚本及原文长度直接复用变量，不能在步骤间替换。
        Ok(next)
    }
}
