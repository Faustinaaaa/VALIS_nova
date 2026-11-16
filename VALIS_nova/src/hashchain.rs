//! 原文 Poseidon 哈希链。普通计算与电路共用 Nova 的参数和 sponge 模式。
use crate::circuit::{scalar, Num, F};
use ff::{Field, PrimeField};
use generic_array::typenum::U5;
use nova_snark::frontend::{
    gadgets::poseidon::{
        Elt, IOPattern, PoseidonConstants, Simplex, Sponge, SpongeAPI, SpongeCircuit, SpongeOp,
        SpongeTrait, Strength,
    },
    ConstraintSystem, SynthesisError,
};
use std::sync::OnceLock;

// 应用域标记：字节链与最终长度绑定使用不同域，避免混淆。
const INIT_DOMAIN: u64 = 0x56414c495303;
const BYTE_DOMAIN: u64 = 0x56414c495301;
const FINAL_DOMAIN: u64 = 0x56414c495302;
fn constants() -> &'static PoseidonConstants<F, U5> {
    static CONSTANTS: OnceLock<PoseidonConstants<F, U5>> = OnceLock::new();
    CONSTANTS.get_or_init(|| Sponge::<F, U5>::api_constants(Strength::Standard))
}

// 新文公开，不需要盐；使用独立域标记区分原文链。
const TARGET_BYTE_DOMAIN: u64 = 0x56414c495304;
const TARGET_FINAL_DOMAIN: u64 = 0x56414c495305;
pub(crate) fn target_commitment(bytes: &[u8]) -> F {
    let state = bytes.iter().fold(F::ZERO, |h, &b| {
        hash(TARGET_BYTE_DOMAIN, h, F::from(b as u64))
    });
    target_finish(state, bytes.len())
}
pub(crate) fn target_finish(state: F, len: usize) -> F {
    hash(TARGET_FINAL_DOMAIN, state, scalar(len))
}
pub(crate) fn target_absorb_if<CS: ConstraintSystem<F>>(
    cs: CS,
    state: &Num,
    byte: &Num,
    enabled: &Num,
) -> Result<Num, SynthesisError> {
    hash_if(TARGET_BYTE_DOMAIN, cs, state, byte, enabled)
}
fn pattern() -> IOPattern {
    IOPattern(vec![SpongeOp::Absorb(3), SpongeOp::Squeeze(1)])
}
fn hash(domain: u64, state: F, item: F) -> F {
    let mut sponge = Sponge::new_with_constants(constants(), Simplex);
    let acc = &mut ();
    sponge.start(pattern(), None, acc);
    SpongeAPI::absorb(&mut sponge, 3, &[F::from(domain), state, item], acc);
    let output = SpongeAPI::squeeze(&mut sponge, 1, acc);
    sponge.finish(acc).expect("fixed Poseidon IO pattern");
    output[0]
}
pub(crate) fn finish(state: F, len: usize) -> F {
    hash(FINAL_DOMAIN, state, scalar(len))
}
pub(crate) fn commitment(bytes: &[u8], salt: F) -> F {
    let state = bytes
        .iter()
        .fold(hash(INIT_DOMAIN, F::ZERO, salt), |state, &byte| {
            hash(BYTE_DOMAIN, state, F::from(byte as u64))
        });
    finish(state, bytes.len())
}
/// 固定计算候选哈希，再用 enabled 选择是否更新；不按操作改变约束形状。
fn hash_if<CS: ConstraintSystem<F>>(
    domain: u64,
    mut cs: CS,
    state: &Num,
    byte: &Num,
    enabled: &Num,
) -> Result<Num, SynthesisError> {
    let output = {
        let mut cs = cs.namespace(|| "poseidon");
        let mut sponge = SpongeCircuit::new_with_constants(constants(), Simplex);
        sponge.start(pattern(), None, &mut cs);
        SpongeAPI::absorb(
            &mut sponge,
            3,
            &[
                Elt::num_from_fr::<CS>(F::from(domain)),
                Elt::Allocated(state.clone()),
                Elt::Allocated(byte.clone()),
            ],
            &mut cs,
        );
        let output = SpongeAPI::squeeze(&mut sponge, 1, &mut cs);
        sponge.finish(&mut cs).expect("fixed Poseidon IO pattern");
        output
    };
    let candidate = Elt::ensure_allocated(&output[0], &mut cs.namespace(|| "hash"))?;
    let next = Num::alloc(cs.namespace(|| "next hash"), || {
        let get = |n: &Num| n.get_value().ok_or(SynthesisError::AssignmentMissing);
        Ok(get(state)? + get(enabled)? * (get(&candidate)? - get(state)?))
    })?;
    cs.enforce(
        || "select hash",
        |lc| lc + enabled.get_variable(),
        |lc| lc + candidate.get_variable() - state.get_variable(),
        |lc| lc + next.get_variable() - state.get_variable(),
    );
    Ok(next)
}
/// 固定 64 位小写十六进制；按 F::to_repr 的小端字节顺序编码。
pub(crate) fn encode(value: F) -> String {
    value
        .to_repr()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
/// 仅检查编码和域元素规范性，不检查承诺是否匹配 witness。
pub(crate) fn decode(text: &str) -> Result<F, String> {
    let mut repr = <F as PrimeField>::Repr::default();
    if text.len() != repr.as_ref().len() * 2
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("field encoding must be canonical lowercase 64-digit hex".into());
    }
    for (i, byte) in repr.as_mut().iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).map_err(|e| e.to_string())?;
    }
    Option::<F>::from(F::from_repr(repr))
        .ok_or("field encoding is not a canonical field element".into())
}

/// 仅首步启用：H(INIT_DOMAIN, 0, private_salt)，其它步骤沿用上步的链。
pub(crate) fn initialize_if<CS: ConstraintSystem<F>>(
    cs: CS,
    state: &Num,
    salt: &Num,
    first: &Num,
) -> Result<Num, SynthesisError> {
    hash_if(INIT_DOMAIN, cs, state, salt, first)
}
pub(crate) fn absorb_if<CS: ConstraintSystem<F>>(
    cs: CS,
    state: &Num,
    byte: &Num,
    enabled: &Num,
) -> Result<Num, SynthesisError> {
    hash_if(BYTE_DOMAIN, cs, state, byte, enabled)
}

/// 从系统安全随机源采样规范域元素，失败时不退回固定盐。
pub(crate) fn random_salt() -> Result<F, rand_core::Error> {
    use rand_core::RngCore;
    loop {
        let mut repr = <F as PrimeField>::Repr::default();
        rand_core::OsRng.try_fill_bytes(repr.as_mut())?;
        if let Some(salt) = Option::<F>::from(F::from_repr(repr)) {
            return Ok(salt);
        }
    }
}
