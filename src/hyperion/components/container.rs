use bitfield_struct::bitfield;
use std::intrinsics::copy;
use std::ptr::{read_unaligned, write_bytes, write_unaligned};

use crate::hyperion::components::context::ContainerTraversalContext;
use crate::hyperion::components::jump_table::{ContainerJumpTable, ContainerJumpTableEntry, CONTAINER_JUMP_TABLE_ENTRIES, TOP_NODE_JUMP_TABLE_ENTRIES, TOP_NODE_JUMP_TABLE_SHIFT};
use crate::hyperion::components::node_header::{as_top_node, get_offset_jump_successor, get_offset_jump_table};
use crate::hyperion::components::operation_context::OperationContext;
use crate::hyperion::internals::atomic_pointer::{AtomicArena, AtomicEmbContainer};
use crate::hyperion::internals::core::{log_to_file, GLOBAL_CONFIG};
use crate::memorymanager::api::{get_pointer, malloc, Arena, HyperionPointer, NUM_ARENAS};

/// The maximum amount of embedded containers.
pub const CONTAINER_MAX_EMBEDDED_DEPTH: usize = 28;

/// Default size of a container. All new containers are initialized to this size.
pub const DEFAULT_CONTAINER_SIZE: u32 = 32;

/// The maximum amount of free bytes in all container instances. If a container exceeds this limit, the container is reallocated.
pub const CONTAINER_MAX_FREE_BYTES: i32 = DEFAULT_CONTAINER_SIZE as i32;

/// Container type, storing nodes.
#[bitfield(u32)]
pub struct Container {
    /// The current size of this container (in bytes). During execution the size might change due to embedding, ejection or reallocation.
    #[bits(19)]
    pub size: u32,

    /// The split delay value of this container.
    ///
    /// The split delay flag delays the splitting of a container instance in certain cases:
    /// 1. The container only contains a single key or the container has already been completely split.
    /// 2. One of the two resulting split candidates is smaller than 3 KiB, which means that splitting would not be advantageous.
    ///
    /// If the split process is aborted for the above reasons, the split delay is increased, which further increases the size required for another
    /// splitting attempt.
    #[bits(2)]
    pub split_delay: usize,

    /// The jump table value of this container.
    ///
    /// The jump table field can be used to address up to 7 container jump tables, with each container jump table storing up to 7 entries.
    #[bits(3)]
    pub jump_table: usize,

    /// The amount of free bytes in this container.
    ///
    /// Free bytes are already allocated and are in a valid memory region, but are currently not used. During execution the amount of free
    /// bytes will change due to embedding, ejection or reallocation.
    #[bits(8)]
    pub free_bytes: u8,
}

impl Container {
    /// Returns the size of the jump table of the calling container.
    ///
    /// # Example
    /// ```rust
    /// use hyperion_rust::hyperion::components::container::Container;
    /// use hyperion_rust::hyperion::components::jump_table::ContainerJumpTable;
    /// let mut container = Container::default();
    /// container.set_jump_table(2);
    ///
    /// assert_eq!(container.get_jump_table_size(), 56);
    /// ```
    pub fn get_jump_table_size(&self) -> usize {
        self.jump_table() * size_of::<ContainerJumpTable>()
    }

    /// Returns the total amount of jump table entries referenced to by this container.
    ///
    /// # Example
    /// ```rust
    /// use hyperion_rust::hyperion::components::container::Container;
    /// let mut container = Container::default();
    /// container.set_jump_table(2);
    ///
    /// assert_eq!(container.get_jump_table_entry_count(), 14);
    /// ```
    #[inline]
    pub fn get_jump_table_entry_count(&self) -> usize {
        self.jump_table() * CONTAINER_JUMP_TABLE_ENTRIES
    }

    /// Returns a pointer to the first jump table entry referenced to by this container.
    #[inline]
    pub fn get_jump_table_pointer(&mut self) -> *mut ContainerJumpTableEntry {
        unsafe { (self as *mut Self).add(1) as *mut ContainerJumpTableEntry }
    }

    /// Returns the size of this container's header.
    ///
    /// # Example
    /// ```rust
    /// use hyperion_rust::hyperion::components::container::{get_container_head_size, Container};
    /// let container = Container::default();
    /// let container_head_size = get_container_head_size();
    ///
    /// assert_eq!(container_head_size, 4);
    /// ```
    #[inline]
    pub fn get_container_head_size(&self) -> usize {
        size_of::<Container>()
    }

    /// Sets the amount of free bytes to the specified value.
    ///
    /// # Example
    /// ```rust
    /// use hyperion_rust::hyperion::components::container::Container;
    /// let mut container = Container::default();
    /// container.set_free_size_left(10);
    ///
    /// assert_eq!(container.free_bytes(), 10);
    /// ```
    #[inline]
    pub fn set_free_size_left(&mut self, size_left: u32) {
        self.set_free_bytes(size_left as u8);
    }

    /// Increments this container's size by 32 Bytes, if necessary.
    ///
    /// `required_minimum` is the minimal container size needed. This function will only perform an increment is necessary. If there is still
    /// enough free space in the container, the increment will be skipped.
    ///
    /// # Returns
    /// - The new size of this container.
    ///
    /// # Example
    /// ```rust
    /// use hyperion_rust::hyperion::components::container::Container;
    /// let mut container = Container::default();
    /// container.set_size(30);
    /// container.increment_container_size(3);
    ///
    /// assert_eq!(container.size(), 62);
    /// ```
    pub fn increment_container_size(&mut self, required_minimum: u32) -> u32 {
        let container_increment = GLOBAL_CONFIG.read().header.container_size_increment();
        self.set_size(self.size() + required_minimum.div_ceil(container_increment) * container_increment);
        log_to_file(&format!("increment_container_size: {} to resulting size {}", required_minimum, self.size()));
        self.size()
    }

    /// Searches for the largest key in the container jump table that is less than or equal to `key_char`.
    ///
    /// # Returns
    /// - The found key if exists, otherwise `0`.
    /// - The corresponding offset of the found key via the mutable reference to offset.
    pub fn get_key_and_offset_with_jump_table(&mut self, key_char: u8, offset: &mut usize) -> u8 {
        log_to_file("get_key_and_offset_with_jump_table");
        let jt_entry: *mut ContainerJumpTableEntry = self.get_jump_table_pointer();

        // Perform a binary search like scan
        let first_match: usize = unsafe {
            let items: usize = CONTAINER_JUMP_TABLE_ENTRIES * self.jump_table();
            let mid: usize = items / 2;
            let mid_entry: *mut ContainerJumpTableEntry = jt_entry.add(mid);
            // Since the jump table entries are sorted in ascending order in respect to their key, the scan can be limited to the first half in some cases
            if (*mid_entry).key() > key_char {
                mid
            } else {
                items
            }
        };

        if let Some((found_key, found_offset)) = (0..first_match).rev().find_map(|i: usize| unsafe {
            let entry: *mut ContainerJumpTableEntry = jt_entry.add(i);
            if (*entry).key() <= key_char {
                Some(((*entry).key(), (*entry).offset()))
            } else {
                None
            }
        }) {
            log_to_file(&format!("get_key_and_offset_with_jump_table; found key: {}, set offset to {}", found_key, found_offset));
            *offset = found_offset;
            return found_key;
        }

        *offset = self.get_container_head_size() + self.get_jump_table_size();
        log_to_file(&format!("get_key_and_offset_with_jump_table; no found key: 0, set offset to {}", self.get_container_head_size() + self.get_jump_table_size()));
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
    log_to_file(&format!("shift container: shift by: {}, amount: {}", shift_len, container_tail));
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

/// Returns the size of this container's header.
///
/// # Example
/// ```rust
/// use hyperion_rust::hyperion::components::container::get_container_head_size;
/// let container_head_size = get_container_head_size();
///
/// assert_eq!(container_head_size, 4);
/// ```
#[inline]
pub fn get_container_head_size() -> usize {
    size_of::<Container>()
}

/// Returns the size of this container's link type.
///
/// # Example
/// ```rust
/// use hyperion_rust::hyperion::components::container::ContainerLink;
/// use hyperion_rust::memorymanager::api::HyperionPointer;
///
/// let hyperion_pointer_size = size_of::<HyperionPointer>();
/// let container_link_size = size_of::<ContainerLink>();
///
/// assert_eq!(hyperion_pointer_size, container_link_size);
/// ```
#[inline]
pub fn get_container_link_size() -> usize {
    size_of::<ContainerLink>()
}

fn update_jump_table(usage_delta: i16, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) {
    if let Some(stored_node) = ocx.top_jump_table_context.top_node.as_mut() {
        if as_top_node(*stored_node).jump_table_present() {
            log_to_file("update jump table");
            let char_to_check: u8 = if ocx.top_jump_table_context.root_container_sub_char_set {
                ocx.top_jump_table_context.root_container_sub_char
            } else {
                ctx.second_char
            };
            log_to_file(&format!("update_jump_table on {}", char_to_check));

            let jump_table: *mut i16 = unsafe { (*stored_node as *const u8).add(get_offset_jump_table(*stored_node)) as *mut i16 };

            (char_to_check as usize >> TOP_NODE_JUMP_TABLE_SHIFT..TOP_NODE_JUMP_TABLE_ENTRIES).fold(-1, |previous_value: i32, i: usize| unsafe {
                let current_pointer: *mut i16 = jump_table.add(i);
                let current_value: i32 = read_unaligned(current_pointer) as i32;
                log_to_file(&format!("previous val: {}, current val: {}", previous_value, current_value));
                assert!(previous_value < current_value);
                write_unaligned(current_pointer, current_value as i16 + usage_delta);
                current_value
            });
        }
    }

    if let Some(predecessor) = ocx.jump_context.predecessor.as_mut() {
        if as_top_node(*predecessor).jump_successor_present() {
            unsafe {
                let target: *mut i16 = (*predecessor as *mut u8).add(get_offset_jump_successor(*predecessor)) as *mut i16;
                let current_value: i16 = read_unaligned(target);
                write_unaligned(target, current_value.wrapping_add(usage_delta));
                log_to_file(&format!("update_jump_table predecessor to {}", read_unaligned(target)));
            }
        }
    }
}

fn update_embedded_container(usage_delta: i16, ocx: &mut OperationContext) {
    if ocx.embedded_traversal_context.embedded_container_depth == 0 {
        return;
    }
    let size = ocx.get_root_container().size();
    log_to_file(&format!("Update embedded container: current stack size: {}", ocx.embedded_traversal_context.embedded_container_depth));
    if let Some(emb_stack) = ocx.embedded_traversal_context.embedded_stack.as_mut() {
        for container in emb_stack.iter_mut().take(ocx.embedded_traversal_context.embedded_container_depth).rev() {
            if let Some(current_em_container) = container.as_mut().map(|c: &mut AtomicEmbContainer| c.borrow_mut()) {
                let current_size: i16 = current_em_container.size() as i16;
                current_em_container.set_size((current_size + usage_delta) as u8);
                log_to_file(&format!("update_embedded_container: current size: {} + usage_delta: {} = {}", current_size, usage_delta, current_em_container.size()));
            }
        }
        if let Some(emb_container) = emb_stack[0].as_mut() {
            log_to_file(&format!("First embedded size: {} < root_size: {}", emb_container.borrow_mut().size(), size));
            assert!((emb_container.borrow_mut().size() as u32) < size);
        }
    }
}

fn update_container_jump_table(ocx: &mut OperationContext, usage_delta: i16) {
    log_to_file(&format!("update_top_node_jump_table_entries: usage_delta: {}", usage_delta));
    if ocx.get_root_container().jump_table() == 0 {
        return;
    }

    let first_jump_table: *mut ContainerJumpTableEntry = get_jump_table_pointer(ocx.embedded_traversal_context.root_container);
    let entries = ocx.get_root_container().get_jump_table_entry_count();

    (0..entries).rev().for_each(|i| unsafe {
        let jump_table_entry: *mut ContainerJumpTableEntry = first_jump_table.add(i);
        if (*jump_table_entry).key() as i32 > ocx.jump_context.top_node_key {
            (*jump_table_entry).set_offset(((*jump_table_entry).offset() as i32 + usage_delta as i32) as usize);
        }
    });
}

/// Updates this container's space property by the given `delta`.
///
/// `delta` can be both positive and negative. A positive delta will decrease the container's free-space properties, a negative delta will
/// increase the container's free-space properties.
///
/// An update of the container's space will also update all top node jump tables and container jump tables stored in this container. Moreover,
/// all embedded containers stored in this container will be updated in their size by the given `delta`.
pub fn update_space(delta: i16, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) {
    log_to_file(&format!("update space usage: {}", delta));
    assert!(ocx.get_root_container().free_bytes() as i16 >= delta);
    let free_bytes: i16 = ocx.get_root_container().free_bytes() as i16;
    ocx.get_root_container().set_free_size_left((free_bytes - delta) as u32);
    update_jump_table(delta, ocx, ctx);
    update_container_jump_table(ocx, delta);
    update_embedded_container(delta, ocx);

    ctx.max_offset = (ocx.get_root_container().size() - ocx.get_root_container().free_bytes() as u32) as usize;
    assert!(ctx.max_offset > size_of::<Container>());
}

/// Returns a pointer to the first jump table entry referenced to by `container`.
#[inline]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn get_jump_table_pointer(container: *mut Container) -> *mut ContainerJumpTableEntry {
    unsafe { container.add(1) as *mut ContainerJumpTableEntry }
}

pub fn initialize_container(arena: *mut Arena) -> HyperionPointer {
    let mut container_pointer: HyperionPointer = malloc(arena, DEFAULT_CONTAINER_SIZE as usize);
    let container: *mut Container = get_pointer(arena, &mut container_pointer, 1, 0) as *mut Container;
    unsafe {
        (*container).set_size(DEFAULT_CONTAINER_SIZE);
        (*container).set_free_size_left(DEFAULT_CONTAINER_SIZE - (*container).get_container_head_size() as u32);
    }
    container_pointer
}

/// The header of an embedded container.
#[bitfield(u8)]
pub struct EmbeddedContainer {
    /// The size of this embedded container (in bytes).
    pub size: u8,
}

#[repr(C, packed)]
pub struct ContainerLink {
    pub ptr: HyperionPointer,
}

pub const ROOT_NODES: usize = if NUM_ARENAS > 1 { 256 } else { 1 };

pub struct RootContainerStats {
    pub puts: i32,
    pub gets: i32,
    pub updates: i32,
    pub range_queries: i32,
    pub range_queries_leaves: i32,
}

pub struct RootContainerEntryInner {
    pub stats: RootContainerStats,
    pub arena: Option<AtomicArena>,
    pub hyperion_pointer: Option<HyperionPointer>, // TODO KEY_PPP
}

pub struct RootContainerEntry {
    pub inner: spin::Mutex<RootContainerEntryInner>,
}

pub struct RootContainerArray {
    pub root_container_entries: [Option<RootContainerEntry>; ROOT_NODES],
}

#[cfg(test)]
mod test_container_header {
    use crate::hyperion::components::container::{Container, EmbeddedContainer};
    #[test]
    fn test_container_retrieval() {
        let size: u32 = 0b1001001011100010110;
        let free_bytes: u8 = 0b00010101;
        let jump_table: usize = 0b101;
        let split_delay: usize = 0b01;

        let container: Container =
            Container::new().with_size(size).with_free_bytes(free_bytes).with_jump_table(jump_table).with_split_delay(split_delay);

        assert_eq!(size_of_val(&container), 4);
        assert_eq!(container.size(), size);
        assert_eq!(container.free_bytes(), free_bytes);
        assert_eq!(container.jump_table(), jump_table);
        assert_eq!(container.split_delay(), split_delay);
    }

    #[test]
    fn test_embedded_container_header() {
        let size: u8 = 0b10010101;
        let emb_container: EmbeddedContainer = EmbeddedContainer::new().with_size(size);

        assert_eq!(size_of_val(&emb_container), 1);
        assert_eq!(emb_container.size(), size);
    }
}
