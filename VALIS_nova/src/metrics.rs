//! 只读取统计信息，不改变电路或证明格式。
use crate::PP;

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
