//! 只读取统计信息，不改变电路或证明格式。
use crate::PP;

/// 独立统计业务电路，避免影响 setup/prove 的计时和内存峰值。
pub(crate) fn breakdown(
    circuit: &crate::circuit::EditCircuit,
) -> Result<(), nova_snark::frontend::SynthesisError> {
    use crate::circuit::{Num, E1};
    use nova_snark::{
        frontend::{test_shape_cs::TestShapeCS, ConstraintSystem, SynthesisError},
        traits::circuit::StepCircuit,
    };
    use std::collections::BTreeMap;
    let mut cs = TestShapeCS::<E1>::new();
    let z = (0..circuit.arity())
        .map(|i| {
            Num::alloc(cs.namespace(|| format!("input {i}")), || {
                Err(SynthesisError::AssignmentMissing)
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    circuit.synthesize(&mut cs, &z)?;
    let mut groups = BTreeMap::<String, usize>::new();
    for (_, _, _, path) in &cs.constraints {
        let parts: Vec<_> = path.split('/').collect();
        let key = if parts[0].starts_with("slot ") {
            parts.get(1).copied().unwrap_or("other slot")
        } else if parts[0].starts_with("source byte range ") {
            "source byte range"
        } else if parts[0].starts_with("target byte range ") {
            "target byte range"
        } else if parts[0].starts_with("payload byte range ") {
            "payload byte range"
        } else if parts[0].starts_with("edit column ") {
            "edit columns"
        } else {
            parts[0]
        };
        *groups.entry(key.to_owned()).or_default() += 1;
    }
    let total = cs.constraints.len();
    println!(
        "business constraints per step: {total}; steps={}",
        circuit.steps
    );
    for (name, count) in groups {
        println!(
            "  {name}: {count} ({:.2}%)",
            count as f64 * 100.0 / total as f64
        );
    }
    Ok(())
}

pub(crate) fn print_constraints(pp: &PP) {
    let (primary, secondary) = pp.num_constraints();
    let (primary_vars, secondary_vars) = pp.num_variables();
    println!("constraints (Nova R1CS, per step): primary={primary}, secondary={secondary}");
    println!("variables (Nova R1CS): primary={primary_vars}, secondary={secondary_vars}");
}

/// Windows 的峰值工作集是进程从启动至今的最高驻留内存，不是单个函数的增量。
#[cfg(windows)]
fn memory_bytes() -> std::io::Result<(usize, usize)> {
    use std::{ffi::c_void, mem::size_of};
    #[repr(C)]
    #[derive(Default)]
    struct Counters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        quota_peak_paged_pool_usage: usize,
        quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize,
        quota_non_paged_pool_usage: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
        private_usage: usize,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
    }
    #[link(name = "psapi")]
    extern "system" {
        fn GetProcessMemoryInfo(process: *mut c_void, counters: *mut Counters, size: u32) -> i32;
    }
    let mut counters = Counters {
        cb: size_of::<Counters>() as u32,
        ..Default::default()
    };
    // 使用当前进程的伪句柄，无需关闭；结构体布局与 PROCESS_MEMORY_COUNTERS_EX 一致。
    let ok = unsafe {
        GetProcessMemoryInfo(
            GetCurrentProcess(),
            &mut counters,
            size_of::<Counters>() as u32,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((counters.working_set_size, counters.peak_working_set_size))
}

pub(crate) fn print_memory() {
    #[cfg(windows)]
    match memory_bytes() {
        Ok((current, peak)) => {
            println!(
            "memory (process working set): current={:.3} MiB; peak={:.3} MiB (process lifetime)",
            current as f64 / 1_048_576.0, peak as f64 / 1_048_576.0)
        }
        Err(error) => eprintln!("memory: unavailable ({error})"),
    }
    #[cfg(not(windows))]
    println!("memory: unavailable (working-set measurement currently supports Windows)");
}

#[cfg(all(test, windows))]
mod tests {
    #[test]
    fn process_memory_is_available() {
        let (current, peak) = super::memory_bytes().unwrap();
        assert!(current > 0);
        assert!(peak >= current);
    }
}
