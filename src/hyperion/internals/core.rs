use std::ffi::c_void;
use std::ptr::{null, null_mut};
use std::sync::atomic::AtomicPtr;
use std::sync::Mutex;

use bitfield_struct::bitfield;
use crate::hyperion::components::container::Container;
use crate::hyperion::internals::atomic_pointer::{AtomicPointer, Atomicu8, CONTAINER_SIZE_TYPE_0};
use crate::hyperion::preprocessor::key_preprocessor::KeyProcessingIDs;
use crate::memorymanager::api::{get_pointer, malloc, Arena, AtomicMemoryPointer, HyperionPointer};

pub type HyperionCallback<T> = fn(key: &mut Atomicu8, key_len: u16, value: &mut AtomicPointer<T>) -> bool;

#[bitfield(u64, order = Msb)]
pub struct GlobalConfigurationHeader {
    #[bits(1)]
    pub initialized: u8,
    #[bits(1)]
    pub thread_keep_alive: u8,
    #[bits(2)]
    pub preprocessor_strategy: KeyProcessingIDs,
    #[bits(8)]
    pub container_size_increment: u8,
    #[bits(16)]
    pub io_threads: u16,
    #[bits(32)]
    pub container_embedding_high_watermark: u32,
    #[bits(4)]
    __: u8
}

pub struct GlobalConfiguration {
    pub header: GlobalConfigurationHeader,
    pub top_level_successor_threshold: u32,
    pub container_embedding_limit: u32,
    pub num_writes_million: i64,
    pub num_reads_million: i64
}

pub static mut GLOBAL_CONFIG: Mutex<GlobalConfiguration> = Mutex::new(GlobalConfiguration {
    header: GlobalConfigurationHeader::new()
        .with_initialized(0)
        .with_thread_keep_alive(0)
        .with_preprocessor_strategy(KeyProcessingIDs::None)
        .with_container_size_increment(32)
        .with_io_threads(1)
        .with_container_embedding_high_watermark(0),
    top_level_successor_threshold: 0,
    container_embedding_limit: 0,
    num_writes_million: 0,
    num_reads_million: 0
});

pub fn initialize_ejected_container(arena: &mut Arena, required_size: u32) -> HyperionPointer {
    let container_size_increment = unsafe { GLOBAL_CONFIG.lock().unwrap().header.container_size_increment() };
    let null_ptr: *const c_void = null();
    let target_size: usize = (((required_size as usize - CONTAINER_SIZE_TYPE_0 + size_of_val(&null_ptr)) / container_size_increment as usize) + 1) * container_size_increment as usize + CONTAINER_SIZE_TYPE_0;
    let mut pointer: HyperionPointer = malloc(arena, target_size);
    let container: &mut Container = unsafe { (get_pointer(arena, &mut pointer, 1, 0) as *mut Container).as_mut().unwrap() };
    container.set_size(target_size as u32);
    container.set_free_size_left((target_size - container.get_container_head_size() as usize) as u32);
    pointer
}