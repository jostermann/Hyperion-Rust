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

use std::intrinsics::copy_nonoverlapping;
use std::mem::MaybeUninit;
use std::ptr;
use std::slice::from_raw_parts;

use bitfield_struct::bitfield;

#[bitfield(u32, debug = true)]
pub struct HyperionPointerHeader {
    /// 6 bit superbin id, ranging from 0 to 63
    #[bits(6)]
    pub superbin_id: u8,

    /// 12 bit chunk id, ranging from 0 to 4095
    #[bits(12)]
    pub chunk_id: u16,

    /// 14 bit metabin id, ranging from 0 to 16383
    #[bits(14)]
    pub metabin_id: u16,
}

#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct HyperionPointer {
    header: HyperionPointerHeader,
    /// 8 bit bin id, ranging from 0 to 255
    bin_id: u8,
}

impl Default for HyperionPointer {
    fn default() -> Self {
        Self {
            bin_id: 0,
            header: HyperionPointerHeader::new().with_superbin_id(0).with_metabin_id(0).with_chunk_id(0),
        }
    }
}

impl HyperionPointer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a superbin id to the current pointer.
    pub fn with_superbin_id(mut self, value: u8) -> Self {
        self.set_superbin_id(value);
        self
    }

    /// Adds a metabin id to the current pointer.
    pub fn with_metabin_id(mut self, value: u16) -> Self {
        self.set_metabin_id(value);
        self
    }

    /// Adds a bin id to the current pointer.
    pub fn with_bin_id(mut self, value: u8) -> Self {
        self.set_bin_id(value);
        self
    }

    /// Adds a chunk id to the current pointer.
    pub fn with_chunk_id(mut self, value: u16) -> Self {
        self.set_chunk_id(value);
        self
    }

    /// Returns the current superbin id from the pointer.
    #[inline(always)]
    pub fn superbin_id(&self) -> u8 {
        read(&raw const self.header).superbin_id()
    }

    /// Returns the current metabin id from the pointer.
    #[inline(always)]
    pub fn metabin_id(&self) -> u16 {
        read(&raw const self.header).metabin_id()
    }

    /// Returns the current bin id from the pointer.
    #[inline(always)]
    pub fn bin_id(&self) -> u8 {
        read(&raw const self.bin_id)
    }

    /// Returns the current chunk id from the pointer.
    #[inline(always)]
    pub fn chunk_id(&self) -> u16 {
        read(&raw const self.header).chunk_id()
    }

    /// Sets the superbin id to the specified value.
    /// # Panics
    /// - if the value is out of bounds [0, 63]
    #[inline(always)]
    pub fn set_superbin_id(&mut self, value: u8) {
        write_header(&raw mut self.header, |hdr: &mut HyperionPointerHeader| hdr.set_superbin_id(value))
    }

    /// Sets the metabin id to the specified value.
    /// # Panicx
    /// - if the value is out of bound [0, 4095]
    #[inline(always)]
    pub fn set_metabin_id(&mut self, value: u16) {
        write_header(&raw mut self.header, |hdr: &mut HyperionPointerHeader| hdr.set_metabin_id(value))
    }

    /// Sets the bin id to the specified value.
    /// # Panics
    /// - if the value is out of bounds [0, 255]
    #[inline(always)]
    pub fn set_bin_id(&mut self, value: u8) {
        write(&raw mut self.bin_id, value)
    }

    /// Sets the chunk id to the specified value.
    /// # Panics
    /// - if the value is out of bounds [0, 16383]
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

/// Reads the contents of `addr` of the unaligned [`HyperionPointer`].
#[allow(unreachable_code)]
#[inline(always)]
fn read<T>(addr: *const T) -> T {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "arm", target_arch = "aarch64"))]
    unsafe {
        return ptr::read_unaligned(addr);
    }

    unsafe {
        let bytes: &[T] = from_raw_parts(addr, 1);
        let mut aligned_value: MaybeUninit<T> = MaybeUninit::<T>::uninit();
        copy_nonoverlapping(bytes.as_ptr(), aligned_value.as_mut_ptr(), 1);
        aligned_value.assume_init()
    }
}

/// Writes the value to `addr` of the unaligned [`HyperionPointer`].
#[allow(unreachable_code)]
#[inline(always)]
fn write<T>(addr: *mut T, value: T) {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "arm", target_arch = "aarch64"))]
    unsafe {
        ptr::write_unaligned(addr, value);
        return;
    }

    unsafe {
        let bytes: *const T = &value as *const T;
        copy_nonoverlapping(bytes, addr, 1);
    }
}

/// Writes the value to `addr` in the header of the unaligned [`HyperionPointer`].
#[allow(unreachable_code)]
#[inline(always)]
fn write_header(addr: *mut HyperionPointerHeader, mod_fn: impl FnOnce(&mut HyperionPointerHeader)) {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "arm", target_arch = "aarch64"))]
    unsafe {
        let mut header: HyperionPointerHeader = ptr::read_unaligned(addr);
        mod_fn(&mut header);
        ptr::write_unaligned(addr, header);
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
mod hyperion_pointer_tests {
    use crate::memorymanager::pointer::hyperion_pointer::HyperionPointer;

    #[test]
    fn test_hyperion_pointer() {
        let mut hyperion_pointer: HyperionPointer = HyperionPointer::default();
        let size = size_of_val(&hyperion_pointer);
        assert_eq!(size, 5, "Expected HyperionPointer size to by 5 bytes, but got {} bytes.", size);
        assert_eq!(
            hyperion_pointer.superbin_id(),
            0,
            "Default initialization of superbin_id is incorrect. Expected 0, but got {}.",
            hyperion_pointer.superbin_id()
        );
        assert_eq!(
            hyperion_pointer.metabin_id(),
            0,
            "Default initialization of metabin_id is incorrect. Expected 0, but got {}.",
            hyperion_pointer.metabin_id()
        );
        assert_eq!(hyperion_pointer.bin_id(), 0, "Default initialization of bin_id is incorrect. Expected 0, but got {}.", hyperion_pointer.bin_id());
        assert_eq!(
            hyperion_pointer.chunk_id(),
            0,
            "Default initialization of chunk_id is incorrect. Expected 0, but got {}.",
            hyperion_pointer.chunk_id()
        );
        hyperion_pointer.set_superbin_id(12);
        hyperion_pointer.set_metabin_id(13);
        hyperion_pointer.set_bin_id(14);
        hyperion_pointer.set_chunk_id(15);
        assert_eq!(hyperion_pointer.superbin_id(), 12, "Setting superbin_id failed. Expected 12, but got {}.", hyperion_pointer.superbin_id());
        assert_eq!(hyperion_pointer.metabin_id(), 13, "Setting metabin_id failed. Expected 13, but got {}.", hyperion_pointer.metabin_id());
        assert_eq!(hyperion_pointer.bin_id(), 14, "Setting bin_id failed. Expected 14, but got {}.", hyperion_pointer.bin_id());
        assert_eq!(hyperion_pointer.chunk_id(), 15, "Setting chunk_id failed. Expected 15, but got {}.", hyperion_pointer.chunk_id());
    }
}
