use bitfield_struct::bitfield;
use libc::pthread_spinlock_t;

use crate::hyperion::components::context::{EmbeddedTraversalContext, OperationContext};
use crate::hyperion::components::jump_table::{SubNodeJumpTable, SubNodeJumpTableEntry, TOPLEVEL_JUMPTABLE_ENTRIES};
use crate::hyperion::internals::atomic_pointer::AtomicArena;
use crate::hyperion::internals::core::GLOBAL_CONFIG;
use crate::memorymanager::api::HyperionPointer;

pub const CONTAINER_MAX_EMBEDDED_DEPTH: usize = 28;

#[bitfield(u32, order = Msb)]
pub struct Container {
    #[bits(19)]
    pub size: u32,

    #[bits(8)]
    pub free_bytes: u8,

    #[bits(3)]
    pub jump_table: u8,

    #[bits(2)]
    pub split_delay: u8
}

impl Container {
    pub fn get_jump_table_size(&self) -> i32 {
        (self.jump_table() as usize * size_of::<SubNodeJumpTable>()) as i32
    }

    pub fn get_jump_table_entry_count(&self) -> i32 {
        (self.jump_table() as usize * TOPLEVEL_JUMPTABLE_ENTRIES) as i32
    }

    pub fn get_jump_table_pointer(&mut self) -> *mut SubNodeJumpTableEntry {
        let container_pointer: *mut Container = self as *mut Self;
        unsafe { container_pointer.add(1) as *mut SubNodeJumpTableEntry }
    }

    pub fn get_jump_table_entry_mut(&mut self) -> &mut SubNodeJumpTableEntry {
        let container_pointer: *mut Container = self as *mut Self;
        unsafe { (container_pointer.add(1) as *mut SubNodeJumpTableEntry).as_mut().unwrap() }
    }

    pub fn get_container_head_size(&self) -> i32 {
        size_of::<Container>() as i32
    }

    pub fn get_container_link_size(&self) -> i32 {
        size_of::<ContainerLink>() as i32
    }

    pub fn set_free_size_left(&mut self, size_left: u32) {
        self.set_free_bytes(size_left as u8);
    }

    pub fn increment_container_size(&mut self, required_minimum: i32) -> u32 {
        let container_increment: u8 = unsafe { GLOBAL_CONFIG.lock().unwrap().header.container_size_increment() };
        let mut factor: i32 = required_minimum / container_increment as i32;
        if required_minimum % container_increment as i32 != 0 {
            factor += 1;
        }
        self.set_size(self.size() + factor as u32 * container_increment as u32);
        self.size()
    }

    pub fn update_top_node_jumptable_entries(&mut self, operation_context: &mut OperationContext, usage_delta: i16) {
        if self.jump_table() == 0 {
            return;
        }
        let top_node_key = operation_context.jump_context.as_mut().unwrap().top_node_key;
        let embedded_context: &mut Option<EmbeddedTraversalContext> = &mut operation_context.embedded_traversal_context;
        let root_container: &mut Container = embedded_context.as_mut().unwrap().root_container;

        let items = TOPLEVEL_JUMPTABLE_ENTRIES * self.jump_table() as usize;
        let jump_table_entry_base: *mut SubNodeJumpTableEntry = root_container.get_jump_table_pointer();
        let mut jump_table_entry: *mut SubNodeJumpTableEntry = jump_table_entry_base;

        for i in (0..items).rev() {
            unsafe {
                jump_table_entry = jump_table_entry_base.add(i);

                if (*jump_table_entry).key() as i32 > top_node_key {
                    let current_offset: u32 = (*jump_table_entry).offset();
                    (*jump_table_entry).set_offset(current_offset + usage_delta as u32);
                } else {
                    return;
                }
            }
        }
    }
}

#[bitfield(u8)]
pub struct EmbeddedContainer {
    pub size: u8
}

#[repr(align(8))]
pub struct ContainerLink {
    ptr: HyperionPointer
}

pub struct RootContainerStats {
    pub puts: i32,
    pub gets: i32,
    pub updates: i32,
    pub range_queries: i32,
    pub write_lock: pthread_spinlock_t
}

pub struct RootContainerEntry {
    pub spinlock: pthread_spinlock_t,
    pub stats: RootContainerStats,
    pub arena: AtomicArena,
    pub hyperion_pointer: HyperionPointer // TODO KEY_PPP
}

pub struct RootContainer {
    pub root_container_entry: RootContainerEntry
}
