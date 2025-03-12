//! Provides the core functionalities for Hyperion pointers.
//!
//! Heap allocations are pretty fast, but many reallocations or allocations
//! that fluctuate widely in size result in significant heap fragmentation.
//! To reduce heap fragmentation, smaller allocations are stored in large memory
//! mapped segments, and only large allocations are placed on the heap. This
//! module refers to smaller allocations in large `mmap` regions.
//!
//! Each Bin stores 4096 chunks, whereby each chunk is a memory segment in which
//! a container from the trie is stored. The memory manager acting as middleware,
//! decouples the trie from the virtual memory. THis allows for the assignment
//! of containers to chunks to be variable.
//!
//! `HyperionPointer` store the id's of all bin types in the memory hierarchy
//! along the path from the superbin to the chunk. This information can be
//! used to retrieve the containers from the chunks at any time.

use bitfield_struct::bitfield;
use std::intrinsics::copy_nonoverlapping;
use std::mem::MaybeUninit;
use std::ptr;
use std::ptr::{read_unaligned, write_unaligned};
use std::slice::from_raw_parts;

#[bitfield(u32)]
pub struct HyperionPointerHeader {
    /// 6 bit superbin id, ranging from 0 to 63
    #[bits(6)]
    pub superbin_id: u8,

    /// 14 bit metabin id, ranging from 0 to 16383
    #[bits(14)]
    pub metabin_id: u16,

    /// 12 bit chunk id, ranging from 0 to 4095
    #[bits(12)]
    pub chunk_id: u16,
}

#[derive(Copy, Clone)]
#[repr(packed)]
pub struct HyperionPointer {
    bin_id: u8,
    header: HyperionPointerHeader,
}

impl HyperionPointer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn default() -> Self {
        Self {
            bin_id: 0,
            header: HyperionPointerHeader::new()
                .with_superbin_id(0)
                .with_metabin_id(0)
                .with_chunk_id(0),
        }
    }

    pub fn with_superbin_id(mut self, value: u8) -> Self {
        self.set_superbin_id(value);
        self
    }

    pub fn with_metabin_id(mut self, value: u16) -> Self {
        self.set_metabin_id(value);
        self
    }

    pub fn with_bin_id(mut self, value: u8) -> Self {
        self.set_bin_id(value);
        self
    }

    pub fn with_chunk_id(mut self, value: u16) -> Self {
        self.set_chunk_id(value);
        self
    }

    #[inline(always)]
    pub fn superbin_id(&self) -> u8 {
        read(&raw const self.header).superbin_id()
    }

    #[inline(always)]
    pub fn metabin_id(&self) -> u16 {
        read(&raw const self.header).metabin_id()
    }

    #[inline(always)]
    pub fn bin_id(&self) -> u8 {
        read(&raw const self.bin_id)
    }

    #[inline(always)]
    pub fn chunk_id(&self) -> u16 {
        read(&raw const self.header).chunk_id()
    }

    #[inline(always)]
    pub fn set_superbin_id(&mut self, value: u8) {
        write_header(&raw mut self.header, |hdr: &mut HyperionPointerHeader| hdr.set_superbin_id(value))
    }

    #[inline(always)]
    pub fn set_metabin_id(&mut self, value: u16) {
        write_header(&raw mut self.header, |hdr: &mut HyperionPointerHeader| hdr.set_metabin_id(value))
    }

    #[inline(always)]
    pub fn set_bin_id(&mut self, value: u8) {
        write(&raw mut self.bin_id, value)
    }

    #[inline(always)]
    pub fn set_chunk_id(&mut self, value: u16) {
        write_header(&raw mut self.header, |hdr: &mut HyperionPointerHeader| hdr.set_chunk_id(value))
    }

    /// Returns `true`, if the calling `HyperionPointer` is an `ExtendedHyperionPointer`.
    /// Returns `false`, otherwise.
    #[inline(always)]
    pub(crate) fn is_extended_pointer(&self) -> bool {
        self.superbin_id() == 0
    }
}

#[allow(unreachable_code)]
#[inline(always)]
fn read<T>(addr: *const T) -> T {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "armv7", target_arch = "aarch64"))]
    unsafe { return ptr::read(addr); }

    unsafe {
        let bytes: &[T] = from_raw_parts(addr, size_of::<T>());
        let mut aligned_value: MaybeUninit<T> = MaybeUninit::<T>::uninit();
        copy_nonoverlapping(bytes.as_ptr(), aligned_value.as_mut_ptr(), size_of::<T>());
        aligned_value.assume_init()
    }
}

#[allow(unreachable_code)]
#[inline(always)]
fn write<T>(addr: *mut T, value: T) {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "armv7", target_arch = "aarch64"))]
    unsafe {
        ptr::write(addr, value);
        return;
    }

    unsafe {
        let bytes: *const T = &value as *const T;
        copy_nonoverlapping(bytes, addr, size_of::<T>());
    }
}

#[allow(unreachable_code)]
#[inline(always)]
fn write_header(addr: *mut HyperionPointerHeader, mod_fn: impl FnOnce(&mut HyperionPointerHeader)) {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "armv7", target_arch = "aarch64"))]
    unsafe {
        let mut header: HyperionPointerHeader = ptr::read(addr);
        mod_fn(&mut header);
        ptr::write(addr, header);
        return;
    }

    unsafe {
        let bytes: &[HyperionPointerHeader] = from_raw_parts(addr, 4);
        let mut aligned_value: MaybeUninit<HyperionPointerHeader> = MaybeUninit::<HyperionPointerHeader>::uninit();
        copy_nonoverlapping(bytes.as_ptr(), aligned_value.as_mut_ptr(), 4);
        let mut header: HyperionPointerHeader = aligned_value.assume_init();
        mod_fn(&mut header);
        let new_bytes: *const HyperionPointerHeader = &header as *const HyperionPointerHeader;
        copy_nonoverlapping(new_bytes, addr, 4);
    }
}


#[cfg(test)]
mod pointer_tests {
    use crate::memorymanager::pointer::hyperion_pointer::HyperionPointer;

    #[test]
    fn test_hyperion_pointer_size() {
        let mut hp2 = HyperionPointer::default();
        let size = size_of_val(&hp2);
        assert_eq!(size, 5);
        assert_eq!(hp2.superbin_id(), 0);
        assert_eq!(hp2.metabin_id(), 0);
        assert_eq!(hp2.bin_id(), 0);
        assert_eq!(hp2.chunk_id(), 0);
        hp2.set_superbin_id(12);
        hp2.set_metabin_id(13);
        hp2.set_bin_id(14);
        hp2.set_chunk_id(15);
        assert_eq!(hp2.superbin_id(), 12);
        assert_eq!(hp2.metabin_id(), 13);
        assert_eq!(hp2.bin_id(), 14);
        assert_eq!(hp2.chunk_id(), 15);
    }
}
