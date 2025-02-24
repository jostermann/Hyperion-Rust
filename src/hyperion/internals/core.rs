use std::sync::atomic::AtomicPtr;
use std::sync::Mutex;

use bitfield_struct::bitfield;

use crate::hyperion::internals::atomic_pointer::{AtomicPointer, Atomicu8};
use crate::hyperion::preprocessor::key_preprocessor::KeyProcessingIDs;
use crate::memorymanager::api::AtomicMemoryPointer;

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
