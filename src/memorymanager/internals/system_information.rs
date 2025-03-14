use std::fs::File;
use std::io::{BufRead, BufReader};
use std::mem::MaybeUninit;
use std::sync::Mutex;

use libc::{sysinfo, sysinfo as sysinfo_t};
use spin::{RwLock, RwLockReadGuard};

#[derive(Debug, Copy, Clone)]
pub struct MemorySettings {
    pub sys_total: u64,
    pub sys_used: u64,
    pub sys_rate: f64,
    pub vm_size: u32
}

static MEMORY_SETTINGS: RwLock<MemorySettings> = RwLock::new(MemorySettings {
    sys_total: 0,
    sys_used: 0,
    sys_rate: 0.0,
    vm_size: 0,
});

static mut MEM_SETTINGS: Mutex<MemorySettings> = Mutex::new(MemorySettings {
    sys_total: 0,
    sys_used: 0,
    sys_rate: 0.0,
    vm_size: 0
});

fn read_stats() {
    let mut mem_settings = MEMORY_SETTINGS.write();
    mem_settings.sys_total = 0;
    mem_settings.sys_used = 0;
    mem_settings.sys_rate = 0.0;
    mem_settings.vm_size = 0;

    if let Ok(file) = File::open("/proc/self/status") {
        let reader = BufReader::new(file);
        for line in reader.lines().map_while(Result::ok) {
            if line.starts_with("VmSize") {
                if let Some(value) = line.split_whitespace().nth(1) {
                    if let Ok(vm_size_kb) = value.parse::<u64>() {
                        mem_settings.vm_size = vm_size_kb as u32;
                        break;
                    }
                }
            }
        }
    }

    let mut info: MaybeUninit<sysinfo_t> = MaybeUninit::uninit();
    unsafe {
        if sysinfo(info.as_mut_ptr()) == 0 {
            let info: sysinfo = info.assume_init();
            let sys_total: u64 = info.totalram * info.mem_unit as u64;
            let sys_used: u64 = (info.totalram - (info.freeram + info.bufferram)) * info.mem_unit as u64;
            let sys_rate: f64 = (mem_settings.vm_size * 1024) as f64 / sys_total as f64;
            mem_settings.sys_total = sys_total;
            mem_settings.sys_used = sys_used;
            mem_settings.sys_rate = sys_rate;
        }
    }
}

pub fn get_memory_stats(force_update: bool) -> RwLockReadGuard<'static, MemorySettings> {
    if force_update {
        read_stats();
    }
    MEMORY_SETTINGS.read()
}

#[cfg(test)]
mod test_sysinfo {
    #[test]
    fn test_current_system() {
        assert_eq!(1, 1);
    }
}
