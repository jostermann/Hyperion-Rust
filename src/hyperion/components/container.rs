use std::ffi::c_void;
use std::ptr::write_bytes;
use bitfield_struct::bitfield;
use libc::{memmove, pthread_spinlock_t};

use crate::hyperion::components::context::{ContainerTraversalContext, EmbeddedTraversalContext, OperationContext};
use crate::hyperion::components::jump_table::{SubNodeJumpTable, SubNodeJumpTableEntry, SUBLEVEL_JUMPTABLE_ENTRIES, SUBLEVEL_JUMPTABLE_SHIFTBITS, TOPLEVEL_JUMPTABLE_ENTRIES};
use crate::hyperion::components::node_header::NodeHeader;
use crate::hyperion::internals::atomic_pointer::{AtomicArena, CONTAINER_SIZE_TYPE_0};
use crate::hyperion::internals::core::GLOBAL_CONFIG;
use crate::memorymanager::api::HyperionPointer;

pub const CONTAINER_MAX_EMBEDDED_DEPTH: usize = 28;
pub const CONTAINER_MAX_FREESIZE: usize = CONTAINER_SIZE_TYPE_0;

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
        let root_container: &mut Container = embedded_context.as_mut().unwrap().root_container.as_mut();

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

    pub unsafe fn wrap_shift_container(&mut self, start_shift: *mut c_void, shift_len: usize) {
        let remaining_length = self.size() as i64 - ((self as *const Container as *const u8).offset_from(start_shift as *const u8) as u8 + self.free_bytes()) as i64;
        if remaining_length > 0 {
            shift_container(start_shift, shift_len, remaining_length as usize)
        }
    }

    pub fn update_space_usage(&mut self, usage_delta: i16, operation_context: &mut OperationContext, container_traversal_context: &mut ContainerTraversalContext) {
        assert!(self.free_bytes() as i16 >= usage_delta);
        let mut i: usize = 0;
        self.set_free_size_left((self.free_bytes() as i16 - usage_delta) as u32);
        let root_container_subchar_set = operation_context.jump_table_sub_context.as_ref().unwrap().root_container_sub_char_set;
        let root_container_subchar = operation_context.jump_table_sub_context.as_ref().unwrap().root_container_sub_char;
        let node = &mut operation_context.jump_table_sub_context.as_mut().unwrap().top_node;

        if node.is_some() {
            let node = node.as_deref_mut().unwrap();
            if node.as_top_node().jump_table() == 1 {
                let char_to_check =
                    if root_container_subchar_set > 0 {
                        root_container_subchar as u8
                    }
                    else {
                        container_traversal_context.second_char
                    };
                i = char_to_check as usize >> SUBLEVEL_JUMPTABLE_SHIFTBITS;

                let jump_table = unsafe { (node as *const NodeHeader as *const c_void).add(node.get_offset_jump_table() as usize) as *mut i16 };
                let mut previous_value: i32 = -1;
                for i in i..SUBLEVEL_JUMPTABLE_ENTRIES {
                    unsafe {
                        previous_value = *(jump_table.add(i)) as i32;
                        *(jump_table.add(i)) += usage_delta;
                    }
                }
            }
        }

        let predecessor = &mut operation_context.jump_context.as_mut().unwrap().predecessor;
        if predecessor.is_some() {
            let predecessor = predecessor.as_deref_mut().unwrap();
            unsafe {
                *((predecessor as *const NodeHeader as *const c_void).add(predecessor.get_offset_jump_table() as usize) as *mut i16) += usage_delta;
            }
        }

        self.update_top_node_jumptable_entries(operation_context, usage_delta);
        let emb_container_depth = operation_context.embedded_traversal_context.as_mut().unwrap().embedded_container_depth;

        if emb_container_depth > 0 {
            let emb_stack = &mut operation_context.embedded_traversal_context.as_mut().unwrap().embedded_stack;
            for i in (0..emb_container_depth as usize).rev() {
                unsafe {
                    let current_em_container = emb_stack[i].borrow_mut();
                    let current_size = current_em_container.size();
                    current_em_container.set_size(current_size + usage_delta as u8);
                }
            }
        }

        container_traversal_context.safe_offset = (self.size() - self.free_bytes() as u32) as i32;
    }
}

pub unsafe fn shift_container(start_shift: *mut c_void, shift_len: usize, container_tail: usize) {
    memmove(start_shift.add(shift_len), start_shift, container_tail);
    write_bytes(start_shift as *mut u8, 0, shift_len);
}

pub fn get_container_link_size() -> usize {
    size_of::<ContainerLink>()
}

#[bitfield(u8)]
pub struct EmbeddedContainer {
    pub size: u8
}

#[repr(align(8))]
pub struct ContainerLink {
    pub ptr: HyperionPointer
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
