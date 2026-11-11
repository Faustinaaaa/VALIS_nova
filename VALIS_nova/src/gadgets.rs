//! 编辑电路使用的 R1CS 辅助组件：求和、独热选择、查表、条件相等。
//! 分配 witness 只提供候选值；真正保证正确性的是后面的乘法/线性约束。

use crate::circuit::{scalar, Num, F};
use ff::{Field, PrimeField};
use nova_snark::frontend::{ConstraintSystem, SynthesisError};

/// 读取变量的候选赋值；缺少赋值时返回错误。本函数本身不生成约束。
fn value(n: &Num) -> Result<F, SynthesisError> {
    n.get_value().ok_or(SynthesisError::AssignmentMissing)
}

/// 8 个布尔位重构域元素，强制其值属于 0..=255，包括私有删除内容。
pub(crate) fn enforce_byte<CS: ConstraintSystem<F>>(
    mut cs: CS,
    byte: &Num,
) -> Result<(), SynthesisError> {
    let mut bits = Vec::with_capacity(8);
    for i in 0..8 {
        let bit = Num::alloc(cs.namespace(|| format!("bit {i}")), || {
            let repr = value(byte)?.to_repr();
            Ok(F::from(((repr.as_ref()[0] >> i) & 1) as u64))
        })?;
        cs.enforce(
            || format!("boolean {i}"),
            |lc| lc + bit.get_variable(),
            |lc| lc + bit.get_variable() - CS::one(),
            |lc| lc,
        );
        bits.push(bit);
    }
    cs.enforce(
        || "byte reconstruction",
        |mut lc| {
            for (i, bit) in bits.iter().enumerate() {
                lc = lc + (F::from(1u64 << i), bit.get_variable());
            }
            lc
        },
        |lc| lc + CS::one(),
        |lc| lc + byte.get_variable(),
    );
    Ok(())
}

/// 约束 out = constant + sum(terms)，用于计算游标、启用标志和查找结果。
pub(crate) fn sum<CS: ConstraintSystem<F>>(
    mut cs: CS,
    terms: &[Num],
    constant: usize,
) -> Result<Num, SynthesisError> {
    let out = Num::alloc(cs.namespace(|| "sum value"), || {
        terms
            .iter()
            .try_fold(scalar(constant), |acc, n| Ok(acc + value(n)?))
    })?;
    // R1CS 形式：(constant + sum(terms)) × 1 = out。
    cs.enforce(
        || "sum relation",
        |mut lc| {
            lc = lc + (scalar(constant), CS::one());
            for n in terms {
                lc = lc + n.get_variable();
            }
            lc
        },
        |lc| lc + CS::one(),
        |lc| lc + out.get_variable(),
    );
    Ok(out)
}

/// 构造 count 个独热选择位。调用方须保证 enabled 是 0 或 1。
/// enabled=1：恰好一个位置为 1，且其编号必须等于 index，从而约束索引范围。
/// enabled=0：全部选择位为 0；不限制 index 的取值，可用于停用填充槽位。
/// count=0 时只能停用，因此空文本不会被错误读取。
pub(crate) fn selectors<CS: ConstraintSystem<F>>(
    mut cs: CS,
    index: &Num,
    enabled: &Num,
    count: usize,
) -> Result<Vec<Num>, SynthesisError> {
    let mut bits = Vec::new();
    for i in 0..count {
        // 此分支只计算 witness，不按分支改变约束形状。
        let bit = Num::alloc(cs.namespace(|| format!("bit {i}")), || {
            Ok(if value(enabled)? == F::ONE && value(index)? == scalar(i) {
                F::ONE
            } else {
                F::ZERO
            })
        })?;
        // bit × (bit - 1) = 0，确保每个选择位只能为 0 或 1。
        cs.enforce(
            || format!("boolean {i}"),
            |lc| lc + bit.get_variable(),
            |lc| lc + bit.get_variable() - CS::one(),
            |lc| lc,
        );
        bits.push(bit);
    }
    // sum(bits) = enabled：启用时选择一个，停用时一个也不选择。
    cs.enforce(
        || "one hot when enabled",
        |mut lc| {
            for bit in &bits {
                lc = lc + bit.get_variable();
            }
            lc
        },
        |lc| lc + CS::one(),
        |lc| lc + enabled.get_variable(),
    );
    // enabled × index = sum(i × bits[i])：绑定指定索引和所选位置。
    cs.enforce(
        || "index matches selected position",
        |lc| lc + enabled.get_variable(),
        |lc| lc + index.get_variable(),
        |mut lc| {
            for (i, bit) in bits.iter().enumerate() {
                lc = lc + (scalar(i), bit.get_variable());
            }
            lc
        },
    );
    Ok(bits)
}

/// 返回 sum(bits[i] × entries[i])；选择位须由 selectors 等约束组件生成。
/// 独热时返回指定元素，全零时返回 0；这里不会重新约束选择位的独热性质。
pub(crate) fn select<CS: ConstraintSystem<F>>(
    mut cs: CS,
    bits: &[Num],
    entries: &[Num],
) -> Result<Num, SynthesisError> {
    assert_eq!(bits.len(), entries.len());
    let products = bits
        .iter()
        .zip(entries)
        .enumerate()
        .map(|(i, (bit, entry))| bit.mul(cs.namespace(|| format!("selected value {i}")), entry))
        .collect::<Result<Vec<_>, _>>()?;
    sum(cs.namespace(|| "lookup result"), &products, 0)
}

/// 条件相等约束：enabled × (a - b) = 0。
/// enabled=1 时强制 a=b，enabled=0 时不限制二者；布尔性由调用方保证。
pub(crate) fn equal_if<CS: ConstraintSystem<F>>(mut cs: CS, enabled: &Num, a: &Num, b: &Num) {
    cs.enforce(
        || "conditional equality",
        |lc| lc + enabled.get_variable(),
        |lc| lc + a.get_variable() - b.get_variable(),
        |lc| lc,
    );
}

/// 要求已消费长度不超过原文长度。剩余长度拆成 8 个字节，不能为负。
/// 从零开始的游标每步最多增加 BLOCK，不会接近业务域的模数。
pub(crate) fn enforce_source_bound<CS: ConstraintSystem<F>>(
    mut cs: CS,
    consumed: &Num,
    old_len: usize,
) -> Result<(), SynthesisError> {
    let mut bytes = Vec::new();
    for i in 0..8 {
        let byte = Num::alloc(cs.namespace(|| format!("remaining byte {i}")), || {
            let remaining = scalar(old_len) - value(consumed)?;
            Ok(F::from(remaining.to_repr().as_ref()[i] as u64))
        })?;
        enforce_byte(cs.namespace(|| format!("remaining range {i}")), &byte)?;
        bytes.push(byte);
    }
    cs.enforce(
        || "consumed plus remaining equals length",
        |mut lc| {
            lc = lc + consumed.get_variable();
            for (i, byte) in bytes.iter().enumerate() {
                lc = lc + (F::from(1u64 << (8 * i)), byte.get_variable());
            }
            lc
        },
        |lc| lc + CS::one(),
        |lc| lc + (scalar(old_len), CS::one()),
    );
    Ok(())
}
