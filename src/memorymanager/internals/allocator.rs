//! Interface between the memory manager and the virtual memory.
//!
//! Provides functions for
//! - automatic allocation
//! - automatic freeing
//! - automatic reallocation
//! - manual allocation on the heap and via `mmap`
//! - manual freeing on the heap and of `mmap`

use std::backtrace::Backtrace;
use std::ffi::{c_int, c_void};
use std::panic::Location;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};

use libc::{calloc,
           free,
           malloc,
           memcpy,
           memset,
           mmap,
           munmap,
           sysconf,
           MAP_ANON,
           MAP_FAILED,
           MAP_NORESERVE,
           MAP_PRIVATE,
           PROT_READ,
           PROT_WRITE,
           _SC_PAGESIZE};

use crate::memorymanager::api::teardown;
use crate::memorymanager::internals::allocator::AllocatedBy::{Heap, Mmap};
use crate::memorymanager::pointer::atomic_memory_pointer::AtomicMemoryPointer;
// pub(crate) const REALLOC_UPPER_LIMIT: u32 = 16777216;

/// Enum defining all allocation types possible in Hyperion's memory manager.
///
/// Can bei either:
/// - Mmap
/// - Heap
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
#[repr(u8)]
pub(crate) enum AllocatedBy {
    /// Used if the memory was reserved using `mmap`.
    Mmap = 0,
    /// Used if the memory was reserved on the heap using `malloc`.
    Heap = 1
}

impl AllocatedBy {
    /// Transforms its states into a 1 bit representation.
    pub(crate) const fn into_bits(self) -> u8 {
        self as _
    }

    /// Transforms its states from an 8 bit value into a named state.
    ///
    /// # Panics
    /// Panics if an invalid allocation state was found.
    pub(crate) const fn from_bits(value: u8) -> Self {
        match value {
            0 => Mmap,
            1 => Heap,
            _ => {
                panic!("Use of undefined alloc type")
            }
        }
    }
}

pub struct AllocatorError<'a> {
    pub message: &'a str,
    pub location: &'static Location<'static>,
    pub backtrace: Backtrace
}

pub static ABORTED: AtomicBool = AtomicBool::new(false);

pub fn abort(error: &mut AllocatorError) {
    if !ABORTED.load(Ordering::SeqCst) {
        ABORTED.store(true, Ordering::SeqCst);
        teardown();
        panic!("Error: {} ({}:{})\nBacktrace:\n{}", error.message, error.location.file(), error.location.line(), error.backtrace);
    }
}

/// Automatically reserves memory, stores a pointer to the allocated memory in the
/// `AtomicMemoryPointer` and returns the allocation type.
///
/// If the requested allocation size is not page aligned, a heap allocation is
/// attempted. If the heap allocation is successful, `Heap` is returned.
/// If the heap allocation fails or the requested allocation size is page
/// aligned, memory is allocated vie `mmap` and `Mmap` is returned.
///
/// # Safety
/// This function operates directly on the virtual memory. Rust cannot check if
/// the allocation parameters are valid.
pub(crate) unsafe fn auto_allocate_memory(ptr: &mut AtomicMemoryPointer, size: usize) -> AllocatedBy {
    let page_size: usize = unsafe { sysconf(_SC_PAGESIZE) as usize };
    if size % page_size != 0 {
        ptr.store(malloc(size));
        if !ptr.get().is_null() {
            memset(ptr.get(), 0, size);
            return Heap;
        }
    }
    ptr.store(allocate_mmap(size));
    if ptr.is_null() {
        abort(&mut AllocatorError {
            message: "Allocation of memory failed",
            location: Location::caller(),
            backtrace: Backtrace::capture()
        })
    }
    Mmap
}

/// Allocates a given size via `mmap`.
///
/// Returns a raw pointer to the allocated memory, if successful.
/// Returns a null pointer, otherwise.
///
/// # Safety
/// This function operates directly on the virtual memory. Rust cannot check if
/// the allocation parameters are valid.
pub(crate) unsafe fn allocate_mmap(size: usize) -> *mut c_void {
    let p_new: *mut c_void = mmap(null_mut(), size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_NORESERVE, -1, 0);
    if p_new == MAP_FAILED {
        null_mut()
    } else {
        p_new
    }
}

pub(crate) unsafe fn allocate_heap(size: usize) -> *mut c_void {
    let p_new: *mut c_void = calloc(size, 1);
    p_new
}

/// Automatically frees the memory pointed to by the given pointer.
///
/// A pointer to a valid memory region must be provided. For mmap'ed memory
/// regions, the correct size of the region must be specified. The allocation
/// type used for allocating the memory must be given.
///
/// Returns `true`, if the freeing was successful.
/// Returns `false`, otherwise.
///
/// # Safety
/// This function operates directly on the virtual memory. Rust cannot check if
/// the allocation parameters are valid.
pub(crate) unsafe fn auto_free_memory(ptr: *mut c_void, size: usize, allocated_by: AllocatedBy) -> bool {
    assert!(!ptr.is_null());
    if allocated_by == Mmap {
        free_mmap(ptr, size)
    } else {
        free_heap(ptr)
    }
}

pub(crate) unsafe fn free_mmap(ptr: *mut c_void, size: usize) -> bool {
    let ret: c_int = munmap(ptr, size);
    ret == 0
}

pub(crate) unsafe fn free_heap(ptr: *mut c_void) -> bool {
    free(ptr);
    true
}

pub(crate) unsafe fn auto_reallocate_memory(
    ptr: &mut AtomicMemoryPointer, old_size: usize, new_size: usize, allocated_by: AllocatedBy
) -> AllocatedBy {
    let old: *mut c_void = ptr.get();
    let copy_size: usize = if old_size < new_size { old_size } else { new_size };
    let mut new: *mut c_void = calloc(new_size, 1);

    if new.is_null() {
        // heap allocation failed
        new = allocate_mmap(new_size);
        if !new.is_null() {
            ptr.store(new);
            return Mmap;
        }
        else {
            abort(&mut AllocatorError {
                message: "Reallocation of memory failed",
                location: Location::caller(),
                backtrace: Backtrace::capture()
            })
        }
    }

    memcpy(new, old, copy_size);
    ptr.clear();
    ptr.store(new);
    assert!(auto_free_memory(old, old_size, allocated_by));
    assert!(!ptr.get().is_null());
    Heap
}
