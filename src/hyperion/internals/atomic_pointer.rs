use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicPtr, Ordering};

use crate::hyperion::components::container::{Container, EmbeddedContainer, RootContainerEntry};
use crate::hyperion::components::context::PathCompressedEjectionContext;
use crate::hyperion::components::node::NodeValue;
use crate::hyperion::components::node_header::NodeHeader;
use crate::memorymanager::api::{get_pointer, malloc, Arena, HyperionPointer};

pub struct AtomicPointer<T> {
    ptr: AtomicPtr<T>
}

impl<T> Clone for AtomicPointer<T> {
    fn clone(&self) -> Self {
        AtomicPointer {
            ptr: AtomicPtr::new(self.ptr.load(Ordering::SeqCst))
        }
    }
}

impl<T> AtomicPointer<T> {
    pub fn new() -> AtomicPointer<T> {
        AtomicPointer {
            ptr: AtomicPtr::new(null_mut())
        }
    }

    pub fn new_from_pointer(ptr: *mut T) -> AtomicPointer<T> {
        let ptr: AtomicPtr<T> = AtomicPtr::new(ptr);
        AtomicPointer { ptr }
    }

    pub fn get(&self) -> *mut T {
        self.ptr.load(Ordering::SeqCst)
    }

    pub fn store(&mut self, ptr: *mut T) {
        self.ptr.store(ptr, Ordering::SeqCst);
    }

    pub fn is_null(&self) -> bool {
        self.get().is_null()
    }

    pub fn is_notnull(&self) -> bool {
        !self.is_null()
    }

    pub fn add_get(&mut self, offset: usize) -> *mut T {
        unsafe { self.get().add(offset) }
    }

    pub fn clear(&mut self) {
        self.store(null_mut())
    }

    pub fn get_as_mut_memory(&mut self) -> *mut c_void {
        self.get() as *mut c_void
    }

    pub fn borrow_mut(&mut self) -> &mut T {
        unsafe { self.get().as_mut().unwrap() }
    }

    pub fn add(&mut self, offset: usize) {
        let ptr: *mut T = self.add_get(offset);
        self.store(ptr);
    }
}

pub type Atomicu8 = AtomicPointer<u8>;
pub type AtomicArena = AtomicPointer<Arena>;
pub type AtomicContainer = AtomicPointer<Container>;
pub type AtomicEmbContainer = AtomicPointer<EmbeddedContainer>;
pub type AtomicHyperionPointer = AtomicPointer<HyperionPointer>;
pub type AtomicHeader = AtomicPointer<NodeHeader>;
pub type AtomicChar = AtomicPointer<u8>;
pub type AtomicRootEntry = AtomicPointer<RootContainerEntry>;
pub type AtomicPCContext = AtomicPointer<PathCompressedEjectionContext>;
pub type AtomicNodeValue = AtomicPointer<NodeValue>;

pub const CONTAINER_SIZE_TYPE_0: usize = 32;

pub fn initialize_container(arena: &mut Arena) -> HyperionPointer {
    let mut container_pointer: HyperionPointer = malloc(arena, CONTAINER_SIZE_TYPE_0);
    let container: *mut Container = get_pointer(arena, &mut container_pointer, 1, 0) as *mut Container;
    unsafe {
        (*container).set_size(CONTAINER_SIZE_TYPE_0 as u32);
        (*container).set_free_size_left(CONTAINER_SIZE_TYPE_0 as u32 - (*container).get_container_head_size() as u32);
    }
    container_pointer
}
