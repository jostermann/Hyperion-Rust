use std::ptr::null_mut;
use std::sync::atomic::{AtomicPtr, Ordering};

use crate::hyperion::components::container::{EmbeddedContainer, RootContainerArray};
use crate::memorymanager::api::Arena;

pub struct AtomicPointer<T> {
    ptr: AtomicPtr<T>,
}

impl<T> Clone for AtomicPointer<T> {
    fn clone(&self) -> Self {
        AtomicPointer {
            ptr: AtomicPtr::new(self.ptr.load(Ordering::SeqCst)),
        }
    }
}

impl<T> Default for AtomicPointer<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> AtomicPointer<T> {
    pub fn new() -> AtomicPointer<T> {
        AtomicPointer {
            ptr: AtomicPtr::new(null_mut()),
        }
    }

    pub fn new_from_pointer(ptr: *mut T) -> AtomicPointer<T> {
        let ptr: AtomicPtr<T> = AtomicPtr::new(ptr);
        AtomicPointer { ptr }
    }

    pub fn get(&self) -> *mut T {
        self.ptr.load(Ordering::SeqCst)
    }

    pub fn get_as_mut_memory(&mut self) -> *mut u8 {
        self.get() as *mut u8
    }

    pub fn borrow_mut(&mut self) -> &mut T {
        unsafe { self.get().as_mut().unwrap() }
    }
}

pub type AtomicEmbContainer = AtomicPointer<EmbeddedContainer>;
pub type AtomicArena = AtomicPointer<Arena>;
pub type AtomicRootContainerArray = AtomicPointer<RootContainerArray>;
