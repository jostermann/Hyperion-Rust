//! AtomicMemoryPointer holds a pointer to mapped memory and provides atomic
//! operations on it.
//!
//! As Rust does not offer native mmap support, data types from the C library
//! must be used. Due to the lack of mmap support, Rust does not offer a
//! built-in pointer type that can point directly to memory mapped regions.
//! Hyperion is a multithreaded application. For multithreading, Rust's
//! borrow checker requires a guarantee at compile time that no parallel accesses
//! to the memory mapped regions can take place.
//!
//! AtomicMemoryPointer stores pointers to the Mmap regions and implements
//! atomic writing and reading on them. This ensures at compile time that
//! these regions cannot be accessed in parallel.

use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicPtr, Ordering};

use crate::memorymanager::pointer::extended_hyperion_pointer::ExtendedHyperionPointer;

/// Wrapper type for an AtomicPointer to a memory mapped region, stored as
/// `*mut c_void`.
pub struct AtomicMemoryPointer {
    ptr: AtomicPtr<c_void>,
}

impl Clone for AtomicMemoryPointer {
    /// Implements cloning the calling AtomicPointer into a new AtomicPointer.
    ///
    /// Clones the calling AtomicPointer into a new AtomicPointer.
    /// Returns the new `AtomicPointer`.
    fn clone(&self) -> Self {
        let mut ptr = AtomicMemoryPointer::new();
        ptr.store(self.ptr.load(Ordering::Relaxed));
        ptr
    }

    /// Implements cloning from a source AtomicPointer into the calling AtomicPointer.
    ///
    /// Clones the AtomicPointer from the source into the calling AtomicPointer.
    fn clone_from(&mut self, source: &Self) {
        self.ptr.store(source.ptr.load(Ordering::SeqCst), Ordering::Relaxed);
    }
}

/// Since all memory mapped regions between the bins and arenas are disjoint,
/// no threads form different arenas can access the same region. Since each arena
/// can onl be used by one thread at a time due to the spinlock, no two threads
/// from the same arena can access the same region. The means that no
/// synchronization is requires when loading or saving.
impl Default for AtomicMemoryPointer {
    fn default() -> Self {
        Self::new()
    }
}

impl AtomicMemoryPointer {
    /// Creates a new AtomicPointer, initialized to `NULL`. Returns the newly
    /// created `AtomicMemoryPointer`.
    pub fn new() -> Self {
        AtomicMemoryPointer {
            ptr: AtomicPtr::new(null_mut()),
        }
    }

    /// Returns a raw pointer to the stored memory region.
    pub fn get(&mut self) -> *mut c_void {
        // No synchronization requires when loading
        self.ptr.load(Ordering::Relaxed)
    }

    /// Returns a raw pointer to the stored memory region.
    pub fn read(&self) -> *const c_void {
        // No synchronization requires when loading
        self.ptr.load(Ordering::Relaxed)
    }

    /// Returns a raw pointer to the stored `ExtendedHyperionPointer`.
    ///
    /// Extended bins store an ExtendedPointer as chunk data.
    /// Returns a raw pointer to the stored memory region, where the contents
    /// of the region are interpreted as `ExtendedHyperionPointer`.
    pub fn get_as_extended(&mut self) -> *mut ExtendedHyperionPointer {
        self.get() as *mut ExtendedHyperionPointer
    }

    /// Stores the given memory region into the calling `AtomicMemoryPointer`.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let atom_ptr: AtomicMemoryPointer = AtomicMemoryPointer::new();
    /// let ptr: *mut c_void =
    ///     mmap(null_mut(), 50, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_NORESERVE, -1, 0);
    /// atom_ptr.store(ptr);
    /// ```
    pub fn store(&mut self, ptr: *mut c_void) {
        // No synchronization needed
        self.ptr.store(ptr, Ordering::Relaxed)
    }

    /// Checks and returns, if the stored memory region is `NULL`.
    ///
    /// Returns `true`, if the stored memory region is `NULL`.
    ///
    /// Returns `false`, if the stored memory region is not `NULL`, i.e. has some data.
    ///
    /// # Example
    /// ```rust
    /// use crate::hyperion_rust::memorymanager::api::AtomicMemoryPointer;
    /// let atom_ptr = AtomicMemoryPointer::new();
    /// assert!(atom_ptr.is_null());
    /// ```
    pub fn is_null(&self) -> bool {
        self.ptr.load(Ordering::Relaxed).is_null()
    }

    /// Checks and returns, if the stored memory region is not `NULL`.
    ///
    /// Returns `true`, if the stored memory region is not `NULL`, i.e. has some data.
    ///
    /// Returns `false`, if the stored memory region is `NULL`.
    ///
    /// # Example
    /// ```rust
    ///  use crate::hyperion_rust::memorymanager::api::AtomicMemoryPointer;
    ///  let atom_ptr = AtomicMemoryPointer::new();
    ///  assert!(!atom_ptr.is_notnull());
    /// ```
    pub fn is_notnull(&self) -> bool {
        !self.is_null()
    }

    /// Returns a raw pointer to the stored memory, moved by the given offset.
    ///
    /// Loads the pointer to the stored memory region, adds the given offset and
    /// returns the modified pointer.
    pub fn add_get(&mut self, offset: usize) -> *mut c_void {
        unsafe { self.get().add(offset) }
    }

    /// Deletes the stored raw pointer to the memory region.
    ///
    /// # Safety
    /// **Warning:**
    /// _Execute this command only, if the stored memory regions is already freed.
    /// Executing this command without manually freeing the memory region will result
    /// in memory leakage!_
    ///
    /// For a safe alternative, use the clear function of
    /// `ExtendedHyperionPointer`.
    pub fn clear(&mut self) {
        self.store(null_mut());
    }
}
