use bitfield_struct::bitfield;
use std::intrinsics::copy;
use std::ptr::{read_unaligned, write_bytes, write_unaligned};

use crate::hyperion::components::context::ContainerTraversalContext;
use crate::hyperion::components::jump_table::{
    SubNodeJumpTable, SubNodeJumpTableEntry, SUBLEVEL_JUMPTABLE_ENTRIES, SUBLEVEL_JUMPTABLE_SHIFTBITS, TOPLEVEL_JUMPTABLE_ENTRIES,
};
use crate::hyperion::components::node_header::{as_top_node, get_offset_jump, get_offset_jump_table};
use crate::hyperion::components::operation_context::OperationContext;
use crate::hyperion::internals::atomic_pointer::{AtomicEmbContainer, CONTAINER_SIZE_TYPE_0};
use crate::hyperion::internals::core::{log_to_file, GLOBAL_CONFIG};
use crate::memorymanager::api::{Arena, HyperionPointer};

pub const CONTAINER_MAX_EMBEDDED_DEPTH: usize = 28;
pub const CONTAINER_MAX_FREESIZE: usize = CONTAINER_SIZE_TYPE_0;

#[bitfield(u32)]
pub struct Container {
    #[bits(19)]
    pub size: u32,

    #[bits(2)]
    pub split_delay: u8,

    #[bits(3)]
    pub jump_table: u8,

    #[bits(8)]
    pub free_bytes: u8,
}

impl Container {
    pub fn get_jump_table_size(&self) -> usize {
        self.jump_table() as usize * size_of::<SubNodeJumpTable>()
    }

    pub fn get_jump_table_entry_count(&self) -> usize {
        self.jump_table() as usize * TOPLEVEL_JUMPTABLE_ENTRIES
    }

    pub fn get_jump_table_pointer(&mut self) -> *mut SubNodeJumpTableEntry {
        unsafe { (self as *mut Self).add(1) as *mut SubNodeJumpTableEntry }
    }

    pub fn get_container_head_size(&self) -> usize {
        size_of::<Container>()
    }

    pub fn set_free_size_left(&mut self, size_left: u32) {
        self.set_free_bytes(size_left as u8);
    }

    pub fn increment_container_size(&mut self, required_minimum: i32) -> u32 {
        log_to_file(&format!("increment_container_size: {}", required_minimum));
        let container_increment: u8 = GLOBAL_CONFIG.read().header.container_size_increment();
        let mut factor: i32 = required_minimum / container_increment as i32;
        if required_minimum % container_increment as i32 != 0 {
            factor += 1;
        }
        self.set_size(self.size() + factor as u32 * container_increment as u32);
        self.size()
    }

    /// Searches for the largest key in the jump table that is less than or equal to `key_char`.
    ///
    /// # Returns
    /// - The found key if exists, otherwise `0`.
    /// - The corresponding offset of the found key via the mutable reference to offset.
    pub fn get_key_and_offset_with_jump_table(&mut self, key_char: u8, offset: &mut usize) -> u8 {
        let jt_entry: *mut SubNodeJumpTableEntry = self.get_jump_table_pointer();

        let first_match: usize = unsafe {
            let items: usize = TOPLEVEL_JUMPTABLE_ENTRIES * self.jump_table() as usize;
            let mid: usize = items / 2;
            let mid_entry: *mut SubNodeJumpTableEntry = jt_entry.add(mid);
            if (*mid_entry).key() > key_char { mid } else { items }
        };

        if let Some((found_key, found_offset)) = (0..first_match).rev().find_map(|i: usize| unsafe {
            let entry: *mut SubNodeJumpTableEntry = jt_entry.add(i);
            if (*entry).key() <= key_char {
                Some(((*entry).key(), (*entry).offset()))
            }
            else {
                None
            }
        }) {
            *offset = found_offset;
            return found_key;
        }

        *offset = self.get_container_head_size() + self.get_jump_table_size();
        0
    }
}

/// Shifts the memory region forward and clears the overwritten space.
///
/// Moves `container_tail` bytes forward by `shift_len` bytes, starting at `start_shift`. All `shift_len` bytes are zeroed.
///
/// # Safety
/// - `start_shift` must be a valid, aligned pointer for both reading and writing.
/// - The memory regions must not overlap.
/// - The caller must ensure that `start_shift + shift_len + container_tail` is a valid memory region.
/// - Misuse can lead to undefined behavior.
pub unsafe fn shift_container(start_shift: *mut u8, shift_len: usize, container_tail: usize) {
    copy(start_shift, start_shift.add(shift_len), container_tail);
    write_bytes(start_shift, 0, shift_len);
}

/// Shifts forward `shift_len` bytes within the container, starting from `start_shift`.
///
/// Shifts all bytes in the container by `shift_len` bytes, starting at `start_shift`. The amount of bytes shifted is determined by the
/// container's size. All `shift_len` bytes are zeroed.
///
/// # Safety
/// - `start_shift` must be a valid, aligned pointer for both reading and writing.
/// - `container` must be a valid, aligned pointer for both reading and writing.
/// - The caller must ensure that `start_shift + shift_len` is within the container's memory region.
pub unsafe fn wrap_shift_container(container: *mut Container, start_shift: *mut u8, shift_len: usize) {
    let container_start: *mut u8 = container as *mut u8;
    let shift_offset: i64 = start_shift.offset_from(container_start) as i64;
    let remaining_length: i64 = ((*container).size() as i64).saturating_sub(shift_offset + (*container).free_bytes() as i64);

    log_to_file(&format!("wrap shift container rem len: {}", remaining_length));

    if remaining_length > 0 {
        shift_container(start_shift, shift_len, remaining_length as usize)
    }
}

pub fn get_container_head_size() -> usize {
    size_of::<Container>()
}

pub fn get_container_link_size() -> usize {
    size_of::<ContainerLink>()
}

fn update_jump_table(usage_delta: i16, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) {
    if let Some(stored_node) = ocx.jump_table_sub_context.top_node.as_mut() {
        if as_top_node(*stored_node).jump_table_present() {
            let char_to_check: u8 = if ocx.jump_table_sub_context.root_container_sub_char_set {
                ocx.jump_table_sub_context.root_container_sub_char
            } else {
                ctx.second_char
            };
            log_to_file(&format!("update_jump_table on {}", char_to_check));

            let jump_table: *mut i16 = unsafe {
                (*stored_node as *const u8).add(get_offset_jump_table(*stored_node)) as *mut i16
            };

            (char_to_check as usize >> SUBLEVEL_JUMPTABLE_SHIFTBITS..SUBLEVEL_JUMPTABLE_ENTRIES)
                .fold(-1, |previous_value: i32, i: usize| unsafe {
                    let current_pointer: *mut i16 = jump_table.add(i);
                    let current_value: i32 = read_unaligned(current_pointer) as i32;
                    assert!(previous_value < current_value);
                    write_unaligned(current_pointer, current_value as i16 + usage_delta);
                    current_value
                });

            /*let mut previous_value: i32 = -1;
            for i in (char_to_check as usize >> SUBLEVEL_JUMPTABLE_SHIFTBITS)..SUBLEVEL_JUMPTABLE_ENTRIES {
                unsafe {
                    let current_pointer: *mut i16 = jump_table.add(i);
                    let current_value: i32 = read_unaligned(current_pointer) as i32;
                    assert!(previous_value < current_value);
                    previous_value = current_value;
                    write_unaligned(current_pointer, current_value as i16 + usage_delta);
                }
            }*/
        }
    }

    if let Some(predecessor) = ocx.jump_context.predecessor.as_mut() {
        if as_top_node(*predecessor).jump_successor_present() {
            unsafe {
                let target: *mut i16 = (*predecessor as *mut u8).add(get_offset_jump(*predecessor)) as *mut i16;
                let current_value: i16 = read_unaligned(target);
                write_unaligned(target, current_value.wrapping_add(usage_delta));
                log_to_file(&format!("update_jump_table predecessor to {}", read_unaligned(target)));
            }
        }
    }
}

fn update_embedded_container(usage_delta: i16, ocx: &mut OperationContext) {
    if let Some(emb_stack) = ocx.embedded_traversal_context.embedded_stack.as_mut() {
        for container in emb_stack.iter_mut().take(ocx.embedded_traversal_context.embedded_container_depth as usize).rev() {
            if let Some(current_em_container) = container.as_mut().map(|c: &mut AtomicEmbContainer| c.borrow_mut()) {
                let current_size: i16 = current_em_container.size() as i16;
                log_to_file(&format!("update_embedded_container: current size: {} + usage_delta: {}", current_size, usage_delta));
                current_em_container.set_size((current_size + usage_delta) as u8);
            }
        }
        if let Some(emb_container) = emb_stack[0].as_mut() {
            assert!(emb_container.borrow_mut().size() < (ocx.get_root_container().size() as u8));
        }
    }
}

fn update_top_node_jump_table_entries(ocx: &mut OperationContext, usage_delta: i16) {
    log_to_file(&format!("update_top_node_jump_table_entries: usage_delta: {}", usage_delta));
    if ocx.get_root_container().jump_table() == 0 {
        return;
    }

    let jump_table_entry_base: *mut SubNodeJumpTableEntry = get_jump_table_pointer(ocx.embedded_traversal_context.root_container);
    let entries = TOPLEVEL_JUMPTABLE_ENTRIES * ocx.get_root_container().jump_table() as usize;

    (0..entries)
        .rev()
        .for_each(|i| unsafe {
        let jump_table_entry: *mut SubNodeJumpTableEntry = jump_table_entry_base.add(i);
        if (*jump_table_entry).key() as i32 > ocx.jump_context.top_node_key {
            (*jump_table_entry).set_offset(((*jump_table_entry).offset() as i32 + usage_delta as i32) as usize);
        }
        else {
            return;
        }
    });

    /*for i in (0..TOPLEVEL_JUMPTABLE_ENTRIES * ocx.get_root_container().jump_table() as usize).rev() {
        unsafe {
            let jump_table_entry: *mut SubNodeJumpTableEntry = jump_table_entry_base.add(i);

            if (*jump_table_entry).key() as i32 > ocx.jump_context.top_node_key {
                (*jump_table_entry).set_offset(((*jump_table_entry).offset() as i32 + usage_delta as i32) as u32);
            } else {
                break;
            }
        }
    }*/
}

pub fn update_space_usage(usage_delta: i16, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) {
    log_to_file(&format!("update space usage: {}", usage_delta));
    assert!(ocx.get_root_container().free_bytes() as i16 >= usage_delta);
    let free_bytes: i16 = ocx.get_root_container().free_bytes() as i16;
    ocx.get_root_container().set_free_size_left((free_bytes - usage_delta) as u32);
    update_jump_table(usage_delta, ocx, ctx);
    update_top_node_jump_table_entries(ocx, usage_delta);
    update_embedded_container(usage_delta, ocx);

    ctx.safe_offset = (ocx.get_root_container().size() - ocx.get_root_container().free_bytes() as u32) as usize;
    assert!(ctx.safe_offset > size_of::<Container>());
}

pub fn get_jump_table_pointer(container: *mut Container) -> *mut SubNodeJumpTableEntry {
    unsafe { container.add(1) as *mut SubNodeJumpTableEntry }
}

#[bitfield(u8)]
pub struct EmbeddedContainer {
    pub size: u8,
}

#[repr(C, packed)]
pub struct ContainerLink {
    pub ptr: HyperionPointer,
}

pub const ROOT_NODES: usize = 1;

pub struct RootContainerStats {
    pub puts: i32,
    pub gets: i32,
    pub updates: i32,
    pub range_queries: i32,
    pub range_queries_leaves: i32,
}

pub struct RootContainerEntryInner {
    pub stats: RootContainerStats,
    pub arena: Option<*mut Arena>,
    pub hyperion_pointer: Option<HyperionPointer>, // TODO KEY_PPP
}

pub struct RootContainerEntry {
    pub inner: spin::Mutex<RootContainerEntryInner>,
}

pub struct RootContainerArray {
    pub root_container_entries: [Option<RootContainerEntry>; ROOT_NODES],
}
