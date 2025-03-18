use crate::hyperion::components::container::DEFAULT_CONTAINER_SIZE;
use crate::hyperion::components::container::{
    get_container_head_size, shift_container, Container, ContainerLink, EmbeddedContainer, RootContainerEntryInner, CONTAINER_MAX_EMBEDDED_DEPTH,
};
use crate::hyperion::components::context::OperationCommand::{Delete, Get, Put};
use crate::hyperion::components::context::{ContainerTraversalContext, ContainerTraversalHeader, EmbeddedTraversalContext, OperationCommand, RangeQueryContext, TraversalContext, TraversalType};
use crate::hyperion::components::jump_table::{ContainerJumpTableEntry, TOPLEVEL_NODE_JUMP_HWM};
use crate::hyperion::components::node::NodeType::{Invalid, LeafNodeWithValue};
use crate::hyperion::components::node::{get_sub_node_key, get_top_node_key, Node, NodeState, NodeValue};
use crate::hyperion::components::node_header::{
    as_raw_compressed_mut, as_sub_node, as_sub_node_mut, as_top_node, as_top_node_mut, call_sub_node, call_top_node, compare_path_compressed_node,
    delete_node, get_child_container_pointer, get_destination_from_top_node_jump_table, get_jump_successor_value, get_node_value,
    get_offset_child_container, get_offset_jump_successor, get_offset_sub_node, get_offset_sub_node_delta, get_offset_sub_node_non_delta,
    get_offset_top_node, get_offset_top_node_delta, get_offset_top_node_non_delta, get_successor, NodeHeader,
};
use crate::hyperion::components::operation_context::initialize_data_for_scan;
use crate::hyperion::components::operation_context::ContainerValidTypes::ContainerValid;
use crate::hyperion::components::operation_context::JumpStates::{JumpPoint1, JumpPoint2, NoJump};
use crate::hyperion::components::operation_context::{
    create_container_jump_table, insert_jump_successor, new_expand, scan_put, scan_put_embedded, scan_put_single, ContainerValidTypes,
    OperationContext,
};
use crate::hyperion::components::return_codes::ReturnCode;
use crate::hyperion::components::return_codes::ReturnCode::{GetFailureNoNode, KeyNotFound, OK};
use crate::hyperion::components::sub_node::ChildLinkType;
use crate::hyperion::components::sub_node::ChildLinkType::{Link, PathCompressed};
use crate::hyperion::components::top_node::TopNode;
use crate::hyperion::preprocessor::key_preprocessor::KeyProcessingIDs;
use crate::memorymanager::api::{
    free, get_all_chained_pointer, get_chained_pointer, get_pointer, is_chained_pointer, malloc, malloc_chained, reallocate, register_chained_memory,
    Arena, HyperionPointer, SegmentChain, CONTAINER_MAX_SPLITS, CONTAINER_SPLIT_BITS,
};
use bitfield_struct::bitfield;
use libc::{calloc, memcmp, size_t};
use std::cmp::Ordering;
use std::ffi::c_void;
use std::fs::OpenOptions;
use std::ptr::{copy, copy_nonoverlapping, null_mut, read_unaligned, write_bytes, write_unaligned};
use std::{fs, io};

pub const CONTAINER_SPLIT_THRESHOLD_A: usize = 12288;
pub const CONTAINER_SPLIT_THRESHOLD_B: usize = 65536;
pub type HyperionCallback = fn(key: *mut u8, key_len: u16, value: *mut u8) -> bool;

#[bitfield(u64)]
pub struct GlobalConfigurationHeader {
    #[bits(1)]
    pub initialized: u8,
    #[bits(1)]
    pub thread_keep_alive: u8,
    #[bits(2)]
    pub preprocessor_strategy: KeyProcessingIDs,
    #[bits(8)]
    pub container_size_increment: u32,
    #[bits(16)]
    pub io_threads: u16,
    #[bits(32)]
    pub container_embedding_high_watermark: u32,
    #[bits(4)]
    __: u8,
}

pub struct GlobalConfiguration {
    pub header: GlobalConfigurationHeader,
    pub top_level_successor_threshold: u32,
    pub container_embedding_limit: u32,
    pub num_writes_million: i64,
    pub num_reads_million: i64,
}

pub static GLOBAL_CONFIG: Lazy<RwLock<GlobalConfiguration>> = Lazy::new(|| {
    RwLock::new(GlobalConfiguration {
        header: GlobalConfigurationHeader::new()
            .with_initialized(0)
            .with_thread_keep_alive(0)
            .with_preprocessor_strategy(KeyProcessingIDs::None)
            .with_container_size_increment(32)
            .with_io_threads(1)
            .with_container_embedding_high_watermark(0),
        top_level_successor_threshold: 0,
        container_embedding_limit: 0,
        num_writes_million: 0,
        num_reads_million: 0,
    })
});

pub fn get_global_cfg() -> *mut GlobalConfiguration {
    GLOBAL_CONFIG.as_mut_ptr()
}

/// Initializes a new container with a required minimum size.
///
/// # Returns
/// - a HyperionPointer to the newly created container.
pub fn initialize_ejected_container(arena: &mut Arena, required_size: u32) -> HyperionPointer {
    let container_size_increment = GLOBAL_CONFIG.read().header.container_size_increment();
    let target_size = (((required_size.wrapping_sub(DEFAULT_CONTAINER_SIZE).wrapping_add(get_container_head_size() as u32))
        / container_size_increment) + 1)
        .wrapping_mul(container_size_increment)
        + DEFAULT_CONTAINER_SIZE;
    log_to_file(&format!("initialize_ejected_container: target size: {}", target_size));
    let mut pointer: HyperionPointer = malloc(arena, target_size as usize);
    let container: *mut Container = get_pointer(arena, &mut pointer, 1, 0) as *mut Container;
    unsafe {
        (*container).set_size(target_size);
        (*container).set_free_size_left(target_size - (*container).get_container_head_size() as u32);
    }
    pointer
}

/// Checks if the split process should be delayed due to some split delay set.
///
/// # Returns
/// - `true` if the split should be delayed.
/// - `false` if the container can be split.
fn should_delay_split(ocx: &mut OperationContext) -> bool {
    if ocx.get_root_container().jump_table() == 0 && ocx.get_root_container().split_delay() < 3 {
        let current_value = ocx.get_root_container().split_delay();
        ocx.get_root_container().set_split_delay(current_value + 1);
        log_to_file(&format!("no jumptable: split_container incremented split delay from {} to {}", current_value, current_value + 1));
        return true;
    }
    false
}

/// Returns a pointer to the first [`ContainerJumpTableEntry`] and the maximum key stored in the jump table.
fn get_jump_table_data(ocx: &mut OperationContext) -> (*mut ContainerJumpTableEntry, u8) {
    let jump_table_entry = ocx.get_root_container().get_jump_table_pointer();
    let jump_table_size = ocx.get_root_container().get_jump_table_entry_count();
    let key_max = unsafe { (*(jump_table_entry.add(jump_table_size - 1))).key() };
    (jump_table_entry, key_max)
}

/// Returns the key of the first node stored in this container.
fn get_first_node_stored_value(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) -> u8 {
    let p_first = unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ctx.current_container_offset) as *mut Node };
    unsafe { (*p_first).key }
}

/// Checks if the split should be aborted.
///
/// One container can be split into a maximal amount of 8 chunks. A chunk i stores the top nodes [32 * i, (32 * (i + 1)) - 1], with i in [0, 7].
/// If the max key and the left init char fall into the same chunk (either by falling into the same range or by having a small difference), the split
/// is aborted.
///
/// # Returns
/// - `true` if the container split must be aborted.
/// - `false` if the container can be split.
fn should_abort_split(ocx: &mut OperationContext, left_init_char: u8, key_max: u8, diff: u8) -> bool {
    let right_chunk = key_max >> (8 - CONTAINER_SPLIT_BITS);
    let left_chunk = left_init_char >> (8 - CONTAINER_SPLIT_BITS);

    if (left_chunk == right_chunk) || diff < (256 / CONTAINER_MAX_SPLITS) as u8 {
        if ocx.get_root_container().split_delay() < 3 {
            let current_value = ocx.get_root_container().split_delay();
            ocx.get_root_container().set_split_delay(current_value + 1);
            log_to_file(&format!(
                "same category or diff to small: split_container incremented split delay from {} to {}",
                current_value,
                current_value + 1
            ));
        }
        return true;
    }
    false
}

/// Returns the last key stored using the container's jump table.
fn compute_right_init_char(ocx: &mut OperationContext, jump_table_entry: *mut ContainerJumpTableEntry, key_max: u8) -> u16 {
    let jump_table_size = ocx.get_root_container().get_jump_table_entry_count();
    let mut right_init_char = unsafe {
        (((*(jump_table_entry.add(jump_table_size / 2))).key() as u16 >> (8 - CONTAINER_SPLIT_BITS)) + 1) * (256 / CONTAINER_MAX_SPLITS) as u16
    };

    if right_init_char > key_max as u16 {
        right_init_char -= 256 / CONTAINER_MAX_SPLITS as u16;
    }
    right_init_char
}

/// Returns a pointer to a position, where the container can be split.
fn find_split_position(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, right_init_char: u16) -> Option<*mut NodeHeader> {
    ctx.header.set_last_top_char_set(true);
    ctx.last_top_char_seen =
        ocx.get_root_container().get_key_and_offset_with_jump_table((right_init_char - 1) as u8, &mut ctx.current_container_offset);
    let mut node_head = unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ctx.current_container_offset) as *mut NodeHeader };
    let mut node_cache = Node {
        header: NodeHeader::new_top_node(TopNode::default()),
        key: 0,
    };
    let mut p_successor = Some(&mut node_cache as *mut Node);
    let mut previous: *mut NodeHeader = null_mut();

    while (ctx.last_top_char_seen as u16) < right_init_char {
        let skipped = get_successor(node_head, &mut p_successor, ocx, ctx, false);
        if skipped == 0 {
            break;
        }
        ctx.current_container_offset += skipped as usize;
        previous = node_head;
        node_head = unsafe { &mut (*(p_successor.expect(ERR_NO_SUCCESSOR))).header as *mut NodeHeader };
        assert_eq!(as_top_node(node_head).container_type(), NodeState::TopNode);
        ctx.last_top_char_seen = get_top_node_key(node_head as *mut Node, ctx);

        // Collect all top nodes falling into the split range of right_init_char
        if (ctx.last_top_char_seen as u16) >= right_init_char {
            break;
        }
        ocx.jump_context.top_node_key = ctx.last_top_char_seen as i32;
    }

    if previous.is_null() {
        // The node as right_init_char has no successor node and cannot be split into a separate container
        if ocx.get_root_container().split_delay() < 3 {
            let current_value = ocx.get_root_container().split_delay();
            ocx.get_root_container().set_split_delay(current_value + 1);
            log_to_file(&format!("previous was NULL: split_container incremented split delay from {} to {}", current_value, current_value + 1));
        }
        return None;
    }
    Some(previous)
}

/// Splits a container into up to 8 chained chunks.
///
/// # Returns
/// - `true` if the split was successful.
/// - `false` if the split was delayed or aborted.
pub fn split_container(ocx: &mut OperationContext) -> bool {
    if should_delay_split(ocx) {
        return false;
    }

    let (jump_table_entry, key_max) = get_jump_table_data(ocx);
    let mut ctx: ContainerTraversalContext = ContainerTraversalContext {
        current_container_offset: ocx.get_root_container().get_container_head_size() + ocx.get_root_container().get_jump_table_size(),
        ..ContainerTraversalContext::default()
    };
    ctx.header.set_last_top_char_set(true);

    let left_init_char = get_first_node_stored_value(ocx, &mut ctx);

    let diff = key_max - left_init_char;
    log_to_file(&format!("split_container: key: {}, left: {}, diff: {}", key_max, left_init_char, diff));
    assert!(diff > 0);

    if should_abort_split(ocx, left_init_char, key_max, diff) {
        return false;
    }

    let right_init_char = compute_right_init_char(ocx, jump_table_entry, key_max);
    if right_init_char < unsafe { (*jump_table_entry).key() as u16 } {
        // Abort, since the container has already been fully split
        if ocx.get_root_container().split_delay() < 3 {
            let current_value = ocx.get_root_container().split_delay();
            ocx.get_root_container().set_split_delay(current_value + 1);
            log_to_file(&format!("right char too small: split_container incremented split delay from {} to {}", current_value, current_value + 1));
        }
        return false;
    }

    let split_position = find_split_position(ocx, &mut ctx, right_init_char);
    if split_position.is_none() {
        return false;
    }

    let previous = split_position.expect(ERR_NO_NODE);

    let basic_head_size = ocx.get_root_container().get_container_head_size();
    let old_container_head = basic_head_size + ocx.get_root_container().get_jump_table_size();
    let mut left_container_size = ctx.current_container_offset - old_container_head;
    let mut right_container_size =
        ocx.get_root_container().size() as i32 - (ctx.current_container_offset as i32 + ocx.get_root_container().free_bytes() as i32);
    log_to_file(&format!(
        "right: {}, head size: {}, old head size: {}, data size: {}, second size: {}",
        right_init_char, basic_head_size, old_container_head, left_container_size, right_container_size
    ));

    if left_container_size < 3072 || right_container_size < 3072 {
        // Abort, since the right or left container is too small after splitting
        if ocx.get_root_container().split_delay() < 3 {
            let current_value = ocx.get_root_container().split_delay();
            ocx.get_root_container().set_split_delay(current_value + 1);
            log_to_file(&format!(
                "split container sizes too small: split_container incremented split delay from {} to {}",
                current_value,
                current_value + 1
            ));
        }
        return false;
    }

    let mut chain_head: HyperionPointer;
    let left_data: *mut c_void;
    let mut src = unsafe { (ocx.get_root_container_pointer() as *mut u8).add(old_container_head) };
    let roundup_factor = 32;
    let required_left = (ctx.current_container_offset as i32 - old_container_head as i32) + get_container_head_size() as i32;
    let target_size_left = ((required_left / roundup_factor) + 2) * roundup_factor;
    let malloc_size_left = target_size_left + 128;
    let is_chain = is_chained_pointer(ocx.arena.unwrap(), ocx.embedded_traversal_context.root_container_pointer);
    log_to_file(&format!(
        "req left: {}, target left: {}, malloc left: {}, is chain: {}",
        required_left, target_size_left, malloc_size_left, is_chain as u8
    ));

    if is_chain {
        // This container is already in a chained memory region. Allocate new memory.
        chain_head = unsafe { *(ocx.embedded_traversal_context.root_container_pointer) };
        left_data = unsafe { calloc(malloc_size_left as size_t, 1) };
    } else {
        // This container was not split in the past. Allocate a new chained memory (using ExtendedHyperionPointers) for the left container.
        chain_head = malloc_chained(ocx.get_arena(), malloc_size_left as usize, 1);
        left_data = get_chained_pointer(ocx.get_arena(), &mut chain_head, left_init_char, false, malloc_size_left as usize);
    }

    let left_target = unsafe { left_data.add(basic_head_size) };
    let left_head = left_data as *mut Container;

    unsafe {
        // Copy the contents of the left region from the original container into the newly allocated left chunk
        copy_nonoverlapping(src, left_target as *mut u8, left_container_size);
    }
    unsafe { (*left_head).set_size(target_size_left as u32) };

    unsafe {
        // If the node at the split position had a jump successor to its sibling node, transfer the jump successor into the newly created chunk.
        if as_top_node(previous).jump_successor_present() {
            let previous_offset = (previous as *mut u8).offset_from(src);
            let new_previous = left_target.add(previous_offset as usize) as *mut NodeHeader;
            let succ_jump = (new_previous as *mut u8).add(get_offset_jump_successor(new_previous));
            let jump_size = read_unaligned(succ_jump as *const u16);
            let shift_amount = jump_size as usize - (size_of::<u16>() + get_offset_jump_successor(new_previous));
            copy(succ_jump.add(size_of::<u16>()), succ_jump, shift_amount);
            write_bytes(succ_jump.add(shift_amount), 0, size_of::<u16>());
            left_container_size -= size_of::<u16>();
            as_top_node_mut(new_previous).set_jump_successor_present(false);
        }

        (*left_head).set_jump_table(0);
        (*left_head).set_free_bytes((target_size_left as usize - (left_container_size + (*left_head).get_container_head_size())) as u8);
    }

    let overallocated_left = malloc_size_left - target_size_left;

    let required_right = right_container_size + get_container_head_size() as i32;
    let target_size_right = ((required_right / roundup_factor) + 1) * roundup_factor;
    let malloc_size_right = target_size_right + 256;
    log_to_file(&format!("req right: {}, target right: {}, malloc right: {}", required_right, target_size_right, malloc_size_right));

    let right_data = if is_chain {
        // The right chunk is already in chained memory. Allocate a new memory region.
        unsafe { calloc(malloc_size_right as size_t, 1) }
    } else {
        // Get a new chained pointer
        get_chained_pointer(ocx.get_arena(), &mut chain_head, right_init_char as u8, true, malloc_size_right as usize)
    };

    let right_head = right_data as *mut Container;
    unsafe {
        (*right_head).set_size(target_size_right as u32);
        (*right_head).set_jump_table(0);
        (*right_head).set_free_bytes((target_size_right as usize - (right_container_size as usize + (*right_head).get_container_head_size())) as u8);
    }
    let overallcoated_right = malloc_size_right - target_size_right;
    unsafe {
        let mut right_target = (right_head as *mut u8).add((*right_head).get_container_head_size());
        src = (ocx.get_root_container_pointer() as *mut u8).add(ctx.current_container_offset);
        let node = src as *mut Node;
        assert_ne!(as_top_node(&mut (*node).header as *mut NodeHeader).type_flag(), Invalid);

        // Copy all original data into the new right chunk
        if as_top_node(&mut (*node).header as *mut NodeHeader).delta() == 0 {
            (*node).key = ctx.last_top_char_seen;
            copy_nonoverlapping(node as *mut u8, right_target, right_container_size as usize);
        } else {
            as_top_node_mut(&mut (*node).header as *mut NodeHeader).set_delta(0);
            let target_node = right_target as *mut Node;
            copy_nonoverlapping(node as *mut u8, target_node as *mut u8, 1);
            (*target_node).key = ctx.last_top_char_seen;

            right_target = right_target.add(2);
            src = src.add(1);
            right_container_size -= 1;
            (*right_head).set_free_bytes((*right_head).free_bytes() - 1);

            if as_top_node(&mut (*node).header as *mut NodeHeader).jump_successor_present() {
                let p_sj = src as *mut u16;
                let current_value = read_unaligned(p_sj);
                write_unaligned(p_sj, current_value + 1);
            }
            copy_nonoverlapping(src, right_target, right_container_size as usize);
        }
    }

    if is_chain {
        register_chained_memory(
            ocx.arena.unwrap(),
            ocx.embedded_traversal_context.root_container_pointer,
            left_init_char,
            left_data,
            target_size_left as usize,
            false,
            overallocated_left,
        );
        register_chained_memory(
            ocx.arena.unwrap(),
            ocx.embedded_traversal_context.root_container_pointer,
            right_init_char as u8,
            right_data,
            target_size_right as usize,
            true,
            overallcoated_right,
        );
    } else {
        // Free the old container
        free(ocx.arena.unwrap(), ocx.embedded_traversal_context.root_container_pointer);
    }

    let mut tmp_ctx = ContainerTraversalContext {
        first_char: left_init_char,
        ..ContainerTraversalContext::default()
    };

    let mut tmp_ocx: OperationContext = OperationContext {
        chained_pointer_hook: tmp_ctx.first_char,
        embedded_traversal_context: EmbeddedTraversalContext {
            root_container_pointer: &mut chain_head as *mut HyperionPointer,
            root_container: get_chained_pointer(ocx.get_arena(), &mut chain_head, tmp_ctx.first_char, false, 0) as *mut Container,
            ..EmbeddedTraversalContext::default()
        },
        arena: ocx.arena,
        ..OperationContext::default()
    };

    create_container_jump_table(&mut tmp_ocx, &mut tmp_ctx);

    let mut tmp_ctx = ContainerTraversalContext {
        first_char: right_init_char as u8,
        ..ContainerTraversalContext::default()
    };

    let mut tmp_ocx = OperationContext {
        chained_pointer_hook: tmp_ctx.first_char,
        embedded_traversal_context: EmbeddedTraversalContext {
            root_container: get_chained_pointer(ocx.get_arena(), &mut chain_head, tmp_ctx.first_char, false, 0) as *mut Container,
            root_container_pointer: &mut chain_head as *mut HyperionPointer,
            ..EmbeddedTraversalContext::default()
        },
        arena: ocx.arena,
        ..OperationContext::default()
    };
    create_container_jump_table(&mut tmp_ocx, &mut tmp_ctx);
    unsafe {
        *(ocx.next_container_pointer.expect(ERR_NO_POINTER)) = chain_head;
    }
    ocx.header.set_next_container_valid(ContainerValid);
    true
}

pub fn scan_meta_embedded(
    ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, node_head_ptr: &mut Option<*mut NodeHeader>,
) -> ReturnCode {
    let mut key;

    while ctx.current_container_offset < (ocx.get_next_embedded_container().size() as usize) {
        let node_head = unsafe { (ocx.get_next_embedded_container_pointer() as *mut u8).add(ctx.current_container_offset) as *mut NodeHeader };
        ctx.header.set_node_type(if as_top_node(node_head).type_flag() == Invalid { 0 } else { 1 });
        ctx.header.set_container_type(as_top_node(node_head).container_type());

        match ctx.as_combined_header() {
            t_type @ (TraversalType::FilledOneCharTopNode | TraversalType::FilledTwoCharTopNode) => {
                key = get_top_node_key(node_head as *mut Node, ctx);
                match key.cmp(&ctx.first_char) {
                    Ordering::Less => {
                        ctx.current_container_offset += get_offset_top_node(node_head);
                        ctx.header.set_last_top_char_set(true);
                        ctx.last_top_char_seen = key;
                    },
                    Ordering::Equal => {
                        if t_type == TraversalType::FilledOneCharTopNode {
                            *node_head_ptr = Some(node_head);
                            return OK;
                        }
                        ctx.current_container_offset += get_offset_top_node(node_head);
                        ctx.header.set_in_first_char_scope(true);
                    },
                    Ordering::Greater => {
                        return GetFailureNoNode;
                    },
                }
            },
            TraversalType::FilledOneCharSubNode | TraversalType::FilledTwoCharSubNode => {
                ctx.current_container_offset += get_offset_sub_node(node_head);
            },
            TraversalType::FilledTwoCharSubNodeInFirstCharScope => {
                key = get_sub_node_key(node_head as *mut Node, ctx, false);
                if key < ctx.second_char {
                    ctx.current_container_offset += get_offset_sub_node(node_head);
                    ctx.header.set_last_sub_char_set(true);
                    ctx.last_sub_char_seen = key;
                    continue;
                }

                if key == ctx.second_char {
                    if ctx.header.end_operation() {
                        *node_head_ptr = Some(node_head);
                        return OK;
                    }

                    match as_sub_node(node_head).child_container() {
                        PathCompressed => {
                            if !compare_path_compressed_node(node_head, ocx) {
                                ocx.header.set_pathcompressed_child(true);
                                ctx.header.set_end_operation(true);
                                *node_head_ptr = Some(node_head);
                                return OK;
                            }
                        },
                        ChildLinkType::None => {
                            return GetFailureNoNode;
                        },
                        _ => {
                            return get_child_container_pointer(node_head, ocx, ctx, false);
                        },
                    }
                }
            },
            _ => {},
        }
    }
    GetFailureNoNode
}

fn scan_meta_phase2(
    ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, node_head_ptr: &mut Option<*mut NodeHeader>, destination: u8,
) -> ReturnCode {
    let mut skip_first = true;
    ctx.last_sub_char_seen = destination;
    let mut node_head = unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ctx.current_container_offset) as *mut NodeHeader };
    if ctx.last_sub_char_seen == 0 {
        if as_top_node(node_head).container_type() == NodeState::TopNode {
            return GetFailureNoNode;
        }
        ctx.last_sub_char_seen = get_sub_node_key(node_head as *mut Node, ctx, false);
    }

    while ctx.current_container_offset < ctx.max_offset {
        if !skip_first {
            if as_top_node(node_head).container_type() == NodeState::TopNode {
                return GetFailureNoNode;
            }
            ctx.last_sub_char_seen = get_sub_node_key(node_head as *mut Node, ctx, true);
        }

        if skip_first {
            skip_first = false;
        }

        match ctx.last_sub_char_seen.cmp(&ctx.second_char) {
            Ordering::Less => {
                ctx.current_container_offset += get_offset_sub_node(node_head);
                node_head = unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ctx.current_container_offset) as *mut NodeHeader };
                continue;
            },
            Ordering::Equal => {
                if ctx.header.end_operation() {
                    *node_head_ptr = Some(node_head);
                    return OK;
                }

                return match as_sub_node(node_head).child_container() {
                    PathCompressed => {
                        if compare_path_compressed_node(node_head, ocx) {
                            ocx.header.set_pathcompressed_child(true);
                            ctx.header.set_end_operation(true);
                            *node_head_ptr = Some(node_head);
                            return OK;
                        }
                        GetFailureNoNode
                    },
                    ChildLinkType::None => GetFailureNoNode,
                    _ => {
                        return get_child_container_pointer(node_head, ocx, ctx, false);
                    },
                };
            },
            Ordering::Greater => {
                return GetFailureNoNode;
            },
        }
    }
    GetFailureNoNode
}

fn scan_meta_single(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, node_head_ptr: &mut Option<*mut NodeHeader>) -> ReturnCode {
    let mut node_head = null_mut();
    let mut key = 0;
    let mut jump_point = NoJump;
    ctx.max_offset = (ocx.get_root_container().size() as i32 - ocx.get_root_container().free_bytes() as i32) as usize;

    initialize_data_for_scan(ocx, ctx, node_head, &mut key, &mut jump_point);

    loop {
        match jump_point {
            NoJump => {
                jump_point = NoJump;
                if ctx.max_offset <= ctx.current_container_offset {
                    return GetFailureNoNode;
                }
                node_head = unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ctx.current_container_offset) as *mut NodeHeader };

                if as_top_node(node_head).container_type() == NodeState::TopNode {
                    jump_point = JumpPoint1;
                    key = get_top_node_key(node_head as *mut Node, ctx);
                    continue;
                }
                ctx.current_container_offset += get_offset_sub_node(node_head);
            },
            JumpPoint1 => {
                jump_point = NoJump;
                match key.cmp(&ctx.first_char) {
                    Ordering::Less => {
                        if as_top_node(node_head).jump_successor_present() {
                            ctx.current_container_offset += get_jump_successor_value(node_head);
                        } else {
                            ctx.current_container_offset += get_offset_top_node(node_head);
                        }
                        ctx.header.set_last_top_char_set(true);
                        ctx.last_top_char_seen = key;
                    },
                    Ordering::Equal => {
                        *node_head_ptr = Some(node_head);
                        return OK;
                    },
                    Ordering::Greater => {
                        return GetFailureNoNode;
                    },
                }
            },
            _ => {},
        }
    }
}

fn scan_meta(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, node_head_ptr: &mut Option<*mut NodeHeader>) -> ReturnCode {
    log_to_file("scan_meta");
    let mut node_head = null_mut();
    let mut topnodes_seen = TOPLEVEL_NODE_JUMP_HWM;
    let mut skip_first = false;
    let mut skip_all = false;

    ctx.max_offset = (ocx.get_root_container().size() as i32 - ocx.get_root_container().free_bytes() as i32) as usize;
    log_to_file(&format!("scan_meta max offset {}", ctx.max_offset));

    if ocx.get_root_container().jump_table() == 0 {
        ctx.current_container_offset = ocx.get_root_container().get_container_head_size();
    } else {
        ocx.jump_context.top_node_key =
            ocx.get_root_container().get_key_and_offset_with_jump_table(ctx.first_char, &mut ctx.current_container_offset) as i32;

        if ocx.jump_context.top_node_key != 0 {
            node_head = unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ctx.current_container_offset) as *mut NodeHeader };
            skip_all = true;
        }
    }

    if !skip_all {
        node_head = unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ctx.current_container_offset) as *mut NodeHeader };
        skip_first = true;
    }

    while ctx.current_container_offset < ctx.max_offset {
        if !skip_all && as_top_node(node_head).container_type() != NodeState::TopNode {
            ocx.jump_context.sub_nodes_seen = 0;

            loop {
                log_to_file("loop sub node meta");
                ctx.current_container_offset += get_offset_sub_node(node_head);
                node_head = unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ctx.current_container_offset) as *mut NodeHeader };
                ocx.jump_context.sub_nodes_seen += 1;

                if ctx.max_offset <= ctx.current_container_offset {
                    return GetFailureNoNode;
                }

                if as_top_node(node_head).container_type() != NodeState::SubNode {
                    break;
                }
            }

            if ocx.jump_context.sub_nodes_seen > (GLOBAL_CONFIG.read().top_level_successor_threshold as i32) {
                ocx.top_jump_table_context.top_node = None;
                node_head = new_expand(ocx, ctx, size_of::<u16>() as u32);
                assert_eq!(as_top_node(node_head).container_type(), NodeState::TopNode);
                let jump_value = unsafe {
                    ((node_head as *mut u8).offset_from(ocx.get_root_container_pointer() as *mut u8) as u16)
                        - ocx.jump_context.top_node_predecessor_offset_absolute as u16
                };
                node_head = insert_jump_successor(ocx, ctx, jump_value);
            }
        }
        if skip_first {
            skip_first = false;
        }

        if !skip_all {
            log_to_file("jumped to LABEL_SAFE2");
            ocx.jump_context.top_node_key = get_top_node_key(node_head as *mut Node, ctx) as i32;
            topnodes_seen -= 1;

            if topnodes_seen == 0 && (ocx.get_root_container().size() > (DEFAULT_CONTAINER_SIZE * 4)) {
                ocx.flush_jump_table_sub_context();
                create_container_jump_table(ocx, ctx);
                ctx.flush();
                ocx.flush_jump_context();
                return scan_meta(ocx, ctx, node_head_ptr);
            }
        }

        if skip_all {
            skip_all = false;
        }

        match ocx.jump_context.top_node_key.cmp(&(ctx.first_char as i32)) {
            Ordering::Less => {
                ocx.jump_context.top_node_predecessor_offset_absolute = ctx.current_container_offset as i32;
                ocx.jump_context.predecessor = Some(node_head);
                ctx.header.set_last_top_char_set(true);
                ctx.last_top_char_seen = ocx.jump_context.top_node_key as u8;

                let successor_present = as_top_node(node_head).jump_successor_present();

                ctx.current_container_offset += if successor_present {
                    get_jump_successor_value(node_head)
                }
                else {
                    get_offset_top_node(node_head)
                };
                node_head = unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ctx.current_container_offset) as *mut NodeHeader };
                skip_first = successor_present;
            },
            Ordering::Equal => {
                if as_top_node(node_head).jump_table_present() {
                    let destination = get_destination_from_top_node_jump_table(node_head, ctx);
                    return scan_meta_phase2(ocx, ctx, node_head_ptr, destination);
                }
                ctx.current_container_offset += get_offset_top_node(node_head);
                return scan_meta_phase2(ocx, ctx, node_head_ptr, 0);
            },
            Ordering::Greater => {
                return GetFailureNoNode;
            },
        }
    }
    GetFailureNoNode
}

type ScanMetaFunction = fn(&mut OperationContext, &mut ContainerTraversalContext, &mut Option<*mut NodeHeader>) -> ReturnCode;
type ScanPutFunction = fn(&mut OperationContext, &mut ContainerTraversalContext) -> ReturnCode;

// OK
pub fn traverse_tree(ocx: &mut OperationContext) -> ReturnCode {
    let mut node_head: Option<*mut NodeHeader> = None;
    let mut scan_meta_cb: ScanMetaFunction = scan_meta;
    let mut scan_put_cb: ScanPutFunction = scan_put;

    loop {
        let mut ctx = ContainerTraversalContext {
            first_char: unsafe { *(ocx.key.unwrap()) },
            second_char: unsafe { *(ocx.key.unwrap().add(1)) },
            ..ContainerTraversalContext::default()
        };

        ctx.header.set_two_chars(true);

        if ocx.key_len_left <= 2 {
            ctx.header.set_end_operation(true);
            if ocx.key_len_left == 1 {
                ctx.header.set_two_chars(false);
                scan_meta_cb = scan_meta_single;
                scan_put_cb = scan_put_single;
            }
        }

        if ocx.header.next_container_valid() == ContainerValid {
            ocx.embedded_traversal_context.root_container =
                get_pointer(ocx.arena.expect(ERR_NO_ARENA), ocx.next_container_pointer.expect(ERR_NO_POINTER), 0, ctx.first_char) as *mut Container;
            assert!(!ocx.embedded_traversal_context.root_container.is_null());
            ocx.header.set_next_container_valid(ContainerValidTypes::Invalid);
            ocx.embedded_traversal_context.root_container_pointer = ocx.next_container_pointer.unwrap();
            log_to_file(&format!("Root container pointer: {:?}", unsafe { *ocx.embedded_traversal_context.root_container_pointer }));
            log_to_file(&format!("Root container: {:?}", unsafe { *ocx.embedded_traversal_context.root_container }));

            match ocx.header.command() {
                Get => {
                    ocx.chained_pointer_hook = ctx.first_char;
                    ocx.embedded_traversal_context.next_embedded_container_offset = 0;
                    let return_code = scan_meta_cb(ocx, &mut ctx, &mut node_head);
                    if return_code != OK {
                        return return_code;
                    }
                    if ctx.header.end_operation() {
                        return get_node_value(node_head.unwrap(), ocx);
                    }
                    ocx.embedded_traversal_context.next_embedded_container_offset = ctx.current_container_offset as i32;
                },
                Put => {
                    ocx.chained_pointer_hook = ctx.first_char;
                    ocx.embedded_traversal_context.next_embedded_container_offset = 0;
                    ocx.flush_jump_table_sub_context();
                    ocx.flush_jump_context();

                    if (ocx.get_root_container().size() as usize)
                        >= (CONTAINER_SPLIT_THRESHOLD_A + CONTAINER_SPLIT_THRESHOLD_B * ocx.get_root_container().split_delay())
                        && split_container(ocx)
                    {
                        continue;
                    }
                    ctx.current_container_offset = ocx.get_root_container().get_container_head_size();
                    let return_code = scan_put_cb(ocx, &mut ctx);
                    assert_eq!(return_code, OK);
                    ocx.embedded_traversal_context.next_embedded_container_offset = ctx.current_container_offset as i32;

                    if ocx.get_root_container().size() <= 2 * DEFAULT_CONTAINER_SIZE && ocx.header.next_container_valid() == ContainerValid {
                        if ocx.container_injection_context.root_container.is_some()
                            && ((ocx.get_root_container().size() as i32
                                + unsafe { *(ocx.container_injection_context.root_container.unwrap()) }.size() as i32)
                                < (GLOBAL_CONFIG.read().container_embedding_limit as i32))
                        {
                            inject_container(ocx);
                            ocx.container_injection_context.root_container = None;
                            ocx.container_injection_context.container_pointer = None;
                        } else {
                            ocx.container_injection_context.root_container = Some(ocx.embedded_traversal_context.root_container);
                            ocx.container_injection_context.container_pointer = Some(ocx.embedded_traversal_context.root_container_pointer);
                        }
                    } else {
                        ocx.container_injection_context.root_container = None;
                        ocx.container_injection_context.container_pointer = None;
                    }
                },
                Delete => {
                    ocx.embedded_traversal_context.next_embedded_container_offset = 0;
                    ocx.flush_jump_context();
                    ocx.flush_jump_table_sub_context();
                    let return_code = scan_meta_cb(ocx, &mut ctx, &mut node_head);
                    if return_code != OK {
                        return return_code;
                    }
                    if ctx.header.end_operation() {
                        return delete_node(node_head.unwrap(), ocx, &mut ctx);
                    }
                    ocx.embedded_traversal_context.next_embedded_container_offset = ctx.current_container_offset as i32;
                },
                _ => {},
            }
        } else {
            ocx.header.set_next_container_valid(ContainerValidTypes::Invalid);

            match ocx.header.command() {
                Put => {
                    ctx.current_container_offset = size_of::<EmbeddedContainer>();
                    let return_code = scan_put_embedded(ocx, &mut ctx);
                    if return_code != OK {
                        return return_code;
                    }
                    ocx.embedded_traversal_context.next_embedded_container_offset += ctx.current_container_offset as i32;
                },
                Get => {
                    ctx.current_container_offset = size_of::<EmbeddedContainer>();
                    let return_code = scan_meta_embedded(ocx, &mut ctx, &mut node_head);
                    if return_code != OK {
                        return return_code;
                    }
                    if ctx.header.end_operation() {
                        return get_node_value(node_head.unwrap(), ocx);
                    }
                    ocx.embedded_traversal_context.next_embedded_container_offset += ctx.current_container_offset as i32;
                },
                Delete => {
                    ctx.current_container_offset = size_of::<EmbeddedContainer>();
                    let return_code = scan_meta_embedded(ocx, &mut ctx, &mut node_head);
                    if return_code != OK {
                        return return_code;
                    }
                    if ctx.header.end_operation() {
                        return delete_node(node_head.unwrap(), ocx, &mut ctx);
                    }
                    ocx.embedded_traversal_context.next_embedded_container_offset += ctx.current_container_offset as i32;
                },
                _ => {},
            }
        }

        if let Some(ref mut key) = ocx.key {
            unsafe { *key = key.add(2) };
        }
        ocx.key_len_left -= 2;

        if ocx.header.next_container_valid() == ContainerValidTypes::Invalid {
            break;
        }
    }
    OK
}

pub fn inject_container(ocx: &mut OperationContext) {
    log_to_file("inject_container (unchecked)");
    log_to_file("inject_container");
    let mut ctx = ContainerTraversalContext {
        header: ContainerTraversalHeader::default(),
        last_top_char_seen: 0,
        last_sub_char_seen: 0,
        current_container_offset: 0,
        max_offset: 0,
        first_char: 0,
        second_char: 0,
    };

    let mut embedded_stack: [Option<*mut EmbeddedContainer>; CONTAINER_MAX_EMBEDDED_DEPTH] = [None; CONTAINER_MAX_EMBEDDED_DEPTH];
    let mut econ_end_stack: [i32; CONTAINER_MAX_EMBEDDED_DEPTH] = [0; CONTAINER_MAX_EMBEDDED_DEPTH];

    let mut target_ptr;
    let mut toplevel_offset = 0;

    ctx.current_container_offset =
        ocx.get_root_container().get_container_head_size() + unsafe { *ocx.get_injection_context().root_container.unwrap() }.get_jump_table_size();

    let mut offset_of_next_cotainer_ptr = if ocx.header.next_container_valid() != ContainerValidTypes::Invalid {
        unsafe { (ocx.next_container_pointer.unwrap() as *mut u8).offset_from(ocx.get_root_container_pointer() as *mut u8) }
    } else {
        0
    };

    let mut top_node_succ_jump = null_mut();
    let mut ctx_emb = ContainerTraversalContext {
        header: ContainerTraversalHeader::default(),
        last_top_char_seen: 0,
        last_sub_char_seen: 0,
        current_container_offset: 0,
        max_offset: 0,
        first_char: 0,
        second_char: 0,
    };

    let offset_head = ocx.get_root_container().get_container_head_size() + ocx.get_root_container().get_jump_table_size();
    let size_injection = ocx.get_root_container().size() as i32 + (ocx.get_root_container().free_bytes() as i32 + offset_head as i32);

    let cache = unsafe { libc::malloc(size_injection as size_t) };
    let mut tmp_cache = cache;
    ctx_emb.current_container_offset += offset_head;
    let mut tmp_offset = ctx_emb.current_container_offset;

    let mut embed_node;

    let mut to_copy = unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ctx_emb.current_container_offset) as *mut NodeHeader };
    let mut diff;
    let mut copied = 0;

    while ctx_emb.current_container_offset < (ocx.get_root_container().size() as usize) {
        embed_node = unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ctx_emb.current_container_offset) as *mut NodeHeader };

        if as_top_node(embed_node).type_flag() == Invalid {
            break;
        }

        if as_sub_node(embed_node).container_type() == NodeState::TopNode {
            assert!(!as_top_node(embed_node).jump_table_present());
            if as_top_node(embed_node).jump_successor_present() {
                diff = ctx_emb.current_container_offset - tmp_offset;
                unsafe {
                    copy_nonoverlapping(to_copy as *mut u8, tmp_cache as *mut u8, diff);
                }
                copied += diff;
                tmp_offset = ctx_emb.current_container_offset;
                unsafe { to_copy = to_copy.add(diff) };
                // copied previous nodes
                // now copy node with jump data
                diff = get_offset_jump_successor(embed_node);
                unsafe {
                    copy_nonoverlapping(to_copy as *mut u8, tmp_cache as *mut u8, diff);
                }
                copied += diff;
                top_node_succ_jump = tmp_cache as *mut NodeHeader;
                as_top_node_mut(top_node_succ_jump).set_jump_successor_present(false);
                unsafe {
                    tmp_cache = tmp_cache.add(diff);
                }
                diff += size_of::<u16>();
                tmp_offset += diff;
                unsafe {
                    to_copy = to_copy.add(diff);
                }

                if ctx_emb.current_container_offset < (offset_of_next_cotainer_ptr as usize) {
                    offset_of_next_cotainer_ptr -= size_of::<u16>() as isize;
                }

                if as_top_node(top_node_succ_jump).type_flag() == LeafNodeWithValue {
                    diff = size_of::<NodeValue>();
                    unsafe {
                        copy_nonoverlapping(to_copy as *mut u8, tmp_cache as *mut u8, diff);
                    }
                    copied += diff;
                    unsafe {
                        tmp_cache = tmp_cache.add(diff);
                    }
                    tmp_offset += diff;
                    unsafe {
                        to_copy = to_copy.add(diff);
                    }
                }
            }
            ctx_emb.current_container_offset += get_offset_sub_node(embed_node);
        } else {
            ctx_emb.current_container_offset += get_offset_sub_node(embed_node);
        }
    }

    diff = ctx_emb.current_container_offset - tmp_offset;
    unsafe {
        copy_nonoverlapping(to_copy as *mut u8, tmp_cache as *mut u8, diff);
    }
    copied += diff;
    unsafe {
        tmp_cache = tmp_cache.add(diff);
    }
    unsafe {
        to_copy = to_copy.add(diff);
    }
    let total_injection_size = copied + size_of::<EmbeddedContainer>();
    let mut jump_point = NoJump;

    'outer_loop: while (unsafe { *ocx.get_injection_context().root_container.unwrap() }.size() as usize) > ctx.current_container_offset {
        match jump_point {
            NoJump => {
                let node_head = unsafe { ocx.get_injection_root_container_pointer().add(ctx.current_container_offset) as *mut NodeHeader };

                if as_top_node(node_head).type_flag() == Invalid {
                    break;
                }

                if as_top_node(node_head).container_type() == NodeState::TopNode {
                    // TOP-Node
                    if as_top_node(node_head).jump_successor_present() {
                        toplevel_offset = ctx.current_container_offset;
                    } else {
                        toplevel_offset = 0;
                    }
                    assert!(!as_top_node(node_head).jump_table_present());
                    ctx.current_container_offset += get_offset_top_node(node_head);
                } else {
                    // SUB-Node
                    match as_sub_node(node_head).child_container() {
                        Link => {
                            target_ptr = unsafe { (node_head as *mut u8).add(get_offset_child_container(node_head)) as *mut HyperionPointer };

                            if unsafe {
                                memcmp(
                                    target_ptr as *mut c_void,
                                    ocx.embedded_traversal_context.root_container_pointer as *mut c_void,
                                    size_of::<HyperionPointer>() as size_t,
                                ) == 0
                            } {
                                return perform_container_injection(
                                    ocx,
                                    &mut ctx,
                                    total_injection_size as i32,
                                    target_ptr,
                                    cache as *mut u8,
                                    copied as i32,
                                    (offset_of_next_cotainer_ptr as i32) - offset_head as i32,
                                    toplevel_offset as i32,
                                    top_node_succ_jump,
                                );
                            }
                        },
                        PathCompressed => {
                            let offset_child_container = get_offset_child_container(node_head);
                            let mut p_e_stack = unsafe { (node_head as *mut u8).add(offset_child_container) as *mut EmbeddedContainer };
                            embedded_stack[0] = Some(p_e_stack);
                            econ_end_stack[0] =
                                unsafe { (*p_e_stack).size() as i32 } + ctx.current_container_offset as i32 + offset_child_container as i32;
                            let mut emb_stack_counter = 0;

                            let mut tmp_node;
                            ctx.current_container_offset += offset_child_container + size_of::<EmbeddedContainer>();

                            while (unsafe { *ocx.get_injection_context().root_container.unwrap() }.size() as usize) > ctx.current_container_offset {
                                if emb_stack_counter > 0 {
                                    while econ_end_stack[emb_stack_counter - 1] == (ctx.current_container_offset as i32) {
                                        emb_stack_counter -= 1;
                                        if emb_stack_counter == 0 {
                                            break;
                                        }
                                    }
                                }

                                if emb_stack_counter == 0 {
                                    jump_point = NoJump;
                                    continue 'outer_loop;
                                }

                                tmp_node = unsafe {
                                    (ocx.get_injection_root_container_pointer() as *mut u8).add(ctx.current_container_offset) as *mut NodeHeader
                                };
                                assert_ne!(as_top_node(tmp_node).type_flag(), Invalid);

                                if as_top_node(tmp_node).container_type() == NodeState::TopNode {
                                    ctx.current_container_offset += get_offset_top_node(tmp_node);
                                } else {
                                    match as_sub_node(tmp_node).child_container() {
                                        ChildLinkType::EmbeddedContainer => {
                                            let emb_offset = get_offset_child_container(tmp_node);
                                            p_e_stack = unsafe { (tmp_node as *mut u8).add(emb_offset) as *mut EmbeddedContainer };
                                            ctx.current_container_offset += emb_offset;
                                            embedded_stack[emb_stack_counter] = Some(p_e_stack);
                                            econ_end_stack[emb_stack_counter] =
                                                (unsafe { (*p_e_stack).size() as usize } + ctx.current_container_offset) as i32;
                                            ctx.current_container_offset += size_of::<EmbeddedContainer>();
                                            continue 'outer_loop;
                                        },
                                        Link => {
                                            target_ptr =
                                                unsafe { (tmp_node as *mut u8).add(get_offset_child_container(tmp_node)) as *mut HyperionPointer };

                                            if unsafe {
                                                memcmp(
                                                    target_ptr as *mut c_void,
                                                    ocx.embedded_traversal_context.root_container_pointer as *mut c_void,
                                                    size_of::<HyperionPointer>() as size_t,
                                                ) == 0
                                            } {
                                                return perform_container_injection(
                                                    ocx,
                                                    &mut ctx,
                                                    total_injection_size as i32,
                                                    target_ptr,
                                                    cache as *mut u8,
                                                    copied as i32,
                                                    (offset_of_next_cotainer_ptr as i32) - offset_head as i32,
                                                    toplevel_offset as i32,
                                                    top_node_succ_jump,
                                                );
                                            }
                                        },
                                        _ => {
                                            ctx.current_container_offset += get_offset_sub_node(node_head);
                                        },
                                    }
                                }
                            }
                            jump_point = JumpPoint1;
                            continue;
                        },
                        _ => {
                            ctx.current_container_offset += get_offset_sub_node(node_head);
                        },
                    }
                }
            },
            JumpPoint1 => unsafe {
                jump_point = NoJump;
                libc::free(cache);
            },
            _ => {
                return;
            },
        }
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn perform_container_injection(
    ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, total_injection_size: i32, mut target_ptr: *mut HyperionPointer, cache: *mut u8,
    copied: i32, next_container_fix: i32, toplevel_offset: i32, mut topnode_succ_jump: *mut NodeHeader,
) {
    log_to_file("perform_container_injection (unchecked)");
    let mut node_head = unsafe { (ocx.get_injection_root_container_pointer() as *mut u8).add(ctx.current_container_offset) as *mut NodeHeader };

    let mut safe_to_free: HyperionPointer = *ocx.get_root_container_hyp_pointer();
    let base_container_delta = total_injection_size - size_of::<HyperionPointer>() as i32;

    if base_container_delta > (unsafe { *ocx.get_injection_context().root_container.unwrap() }.free_bytes() as i32) {
        ocx.flush_jump_context();
        ocx.flush_jump_table_sub_context();
        assert!(ocx.path_compressed_ejection_context.is_none());

        let old_free = unsafe { *ocx.get_injection_context().root_container.unwrap() }.free_bytes() as i32;
        let mut new_size = (((unsafe { *ocx.get_injection_context().root_container.unwrap() }.size() as i32) + base_container_delta - old_free)
            / DEFAULT_CONTAINER_SIZE as i32)
            * DEFAULT_CONTAINER_SIZE as i32;

        if new_size <= ((unsafe { *ocx.get_injection_context().root_container.unwrap() }.size() as i32) + base_container_delta - old_free) {
            new_size += DEFAULT_CONTAINER_SIZE as i32;
        }

        let delta = new_size - ocx.get_injection_root_container().size() as i32;
        ocx.container_injection_context.container_pointer = Some(&mut reallocate(
            ocx.get_arena(),
            unsafe { ocx.container_injection_context.container_pointer.unwrap().as_mut().unwrap() },
            new_size as usize,
            ocx.chained_pointer_hook,
        ));
        /*ocx.container_injection_context.container_pointer = Some(
            &mut reallocate(ocx.get_arena(), unsafe { ocx.container_injection_context.container_pointer.unwrap().as_mut().unwrap() }, new_size as usize, ocx.chained_pointer_hook) as *mut HyperionPointer
        );*/
        ocx.container_injection_context.root_container =
            Some(get_pointer(ocx.get_arena(), ocx.container_injection_context.container_pointer.expect(ERR_NO_POINTER), 1, ocx.chained_pointer_hook)
                as *mut Container);
        node_head = unsafe { (ocx.get_injection_root_container_pointer() as *mut u8).add(ctx.current_container_offset) as *mut NodeHeader };
        assert!(as_top_node(node_head).jump_successor_present());
        assert_ne!(as_top_node(node_head).type_flag(), Invalid);
        target_ptr = unsafe { (node_head as *mut u8).add(get_offset_child_container(node_head)) as *mut HyperionPointer };
        ocx.get_injection_root_container().set_size(new_size as u32);
        ocx.get_injection_root_container().set_free_bytes((delta + old_free) as u8);
        ocx.get_injection_root_container().set_split_delay(0);
    }

    let shift_start = unsafe { (target_ptr as *mut u8).add(size_of::<HyperionPointer>()) };
    let offset = unsafe { shift_start.offset_from(ocx.get_injection_root_container_pointer() as *mut u8) };
    let tail = ocx.get_injection_root_container().size() as i32 - offset as i32 + ocx.get_injection_root_container().free_bytes() as i32;
    unsafe {
        shift_container(shift_start, base_container_delta as usize, tail as usize);
    }

    let target = target_ptr as *mut EmbeddedContainer;
    unsafe {
        (*target).set_size(total_injection_size as u8);
        copy_nonoverlapping(cache, (target as *mut u8).add(size_of::<EmbeddedContainer>()), copied as usize);
    }
    let size_left = ocx.get_injection_root_container().size() - base_container_delta as u32;
    ocx.get_root_container().set_free_size_left(size_left);

    as_sub_node_mut(node_head).set_child_container(ChildLinkType::EmbeddedContainer);

    ocx.next_container_pointer =
        unsafe { Some((target as *mut u8).add(size_of::<EmbeddedContainer>() + next_container_fix as usize) as *mut HyperionPointer) };
    free(ocx.get_arena(), &mut safe_to_free);

    if toplevel_offset != 0 {
        topnode_succ_jump = unsafe { (ocx.get_injection_root_container_pointer() as *mut u8).add(toplevel_offset as usize) as *mut NodeHeader };
        let jump_val = unsafe { (topnode_succ_jump as *mut u8).add(get_offset_jump_successor(topnode_succ_jump)) as *mut u16 };
        unsafe {
            *jump_val += base_container_delta as u16;
        }
    }

    if ocx.get_injection_root_container().jump_table() > 0 {
        ocx.embedded_traversal_context.root_container = ocx.container_injection_context.root_container.unwrap();
        ocx.embedded_traversal_context.root_container_pointer = ocx.container_injection_context.container_pointer.unwrap();
        create_container_jump_table(ocx, ctx);
    }
    unsafe {
        libc::free(cache as *mut c_void);
    }
}

struct TrieStats {
    pub num_internal_nodes: i64,
    pub num_embedded_container: i64,
    pub num_delta_encoded: i64,
    pub path_compressed: [i64; 128],
    pub delta_enc: [i64; 256],
    pub top_jumps: [i64; 8],
    pub cont_splitting_increment: [i64; 4],
}

use crate::hyperion::internals::errors::{ERR_NO_ARENA, ERR_NO_NODE, ERR_NO_POINTER, ERR_NO_SUCCESSOR, ERR_NO_VALUE};
use once_cell::sync::Lazy;
use spin::RwLock;

static TRIE_STATS: Lazy<RwLock<TrieStats>> = Lazy::new(|| {
    RwLock::new(TrieStats {
        num_internal_nodes: 0,
        num_embedded_container: 0,
        num_delta_encoded: 0,
        path_compressed: [0; 128],
        delta_enc: [0; 256],
        top_jumps: [0; 8],
        cont_splitting_increment: [0; 4],
    })
});

#[allow(clippy::not_unsafe_ptr_arg_deref, dead_code, unused_variables)]
pub fn stats_container(container: *mut Container) {
    #[cfg(feature = "triestats")]
    {
        unsafe {
            TRIE_STATS.write().top_jumps[(*container).jump_table() as usize] += 1;
            TRIE_STATS.write().cont_splitting_increment[(*container).split_delay() as usize] += 1;
        }
    }
}

pub fn range_report_container(rqc: &mut RangeQueryContext, cb: HyperionCallback) -> ReturnCode {
    let tree_ctx = &mut rqc.stack[rqc.current_stack_depth as usize].expect(ERR_NO_VALUE);
    log_range(&format!("range_report_container: rqc current_key_offset: {}, stack_depth {}", rqc.current_key_offset, rqc.current_stack_depth));
    let top = unsafe { rqc.current_key.add(rqc.current_key_offset as usize) };
    let sub = unsafe { top.add(1) };
    log_range(&format!("range_report_container: top {}, sub {}", unsafe { *top }, unsafe { *sub }));
    let mut segment_chain = SegmentChain::default();
    let element_count: usize = if tree_ctx.hyperion_pointer.superbin_id() == 0 {
        get_all_chained_pointer(&mut segment_chain, rqc.arena, &mut tree_ctx.hyperion_pointer) as usize
    } else {
        segment_chain.pointer[0].store(get_pointer(rqc.arena, &mut tree_ctx.hyperion_pointer, 0, 0));
        1
    };
    log_range(&format!("element count: {}", element_count));

    for i in 0..element_count {
        log_range(&format!("for i: {}", i));
        let container = segment_chain.pointer[i].get() as *mut Container;
        stats_container(container);
        unsafe { *top = segment_chain.chars[i] };
        tree_ctx.offset = get_container_head_size() + unsafe { (*container).get_jump_table_size() };
        let data_end = unsafe { (*container).size() - (*container).free_bytes() as u32 };

        loop {
            log_range("loop");
            let node_head = unsafe { (container as *mut u8).add(tree_ctx.offset) as *mut NodeHeader };

            #[cfg(feature = "triestats")]
            {
                TRIE_STATS.write().num_internal_nodes += 1;
                if as_top_node(node_head).delta() > 0 {
                    TRIE_STATS.write().num_delta_encoded += 1;
                }
            }

            if as_top_node(node_head).container_type() == NodeState::TopNode {
                if as_top_node(node_head).delta() != 0 {
                    unsafe {
                        log_range(&format!("current top: {}", unsafe { *top }));
                        log_range(&format!("top delta: {}", as_top_node(node_head).delta()));
                        *top += as_top_node(node_head).delta();
                        log_range(&format!("set top to: {}", *top));
                    }
                    if !call_top_node(node_head, rqc, cb) {
                        return OK;
                    }
                    tree_ctx.offset += get_offset_top_node_delta(node_head);
                    log_range(&format!("update1: {}", tree_ctx.offset));
                } else {
                    unsafe {
                        *top = (*top).wrapping_add(*(node_head as *mut u8).add(size_of::<NodeHeader>()));
                        // *top += *(node_head as *mut u8).add(size_of::<NodeHeader>());
                        log_range(&format!("set top to: {}", *top));
                    }
                    if !call_top_node(node_head, rqc, cb) {
                        return OK;
                    }
                    tree_ctx.offset += get_offset_top_node_non_delta(node_head);
                    log_range(&format!("update2: {}", tree_ctx.offset));
                }
                unsafe {
                    *sub = 0;
                }

                #[cfg(feature = "triestats")]
                {
                    let x: i32 = if as_top_node(node_head).delta() != 0 {
                        as_top_node(node_head).delta() as i32
                    } else {
                        unsafe { *(node_head as *mut u8).add(size_of::<NodeHeader>()) as i32 }
                    };
                    assert!(x > 0);
                    assert!(x < 256);
                    TRIE_STATS.write().delta_enc[x as usize] += 1;
                }
            } else if as_sub_node(node_head).delta() != 0 {
                unsafe {
                    log_range(&format!("current sub: {}", unsafe { *sub }));
                    log_range(&format!("sub delta: {}", as_sub_node(node_head).delta()));
                    *sub += as_sub_node(node_head).delta();
                    log_range(&format!("set sub to: {}", *sub));
                }

                #[cfg(feature = "triestats")]
                {
                    TRIE_STATS.write().delta_enc[as_sub_node(node_head).delta() as usize] += 1;
                }

                if !handle_report_sub_node(node_head, rqc, cb) {
                    return OK;
                }
                tree_ctx.offset += get_offset_sub_node_delta(node_head);
                log_range(&format!("update3: {}", tree_ctx.offset));
            } else {
                unsafe {
                    *sub = *(node_head as *mut u8).add(size_of::<NodeHeader>());
                    log_range(&format!("set sub to: {}", *sub));
                }

                #[cfg(feature = "triestats")]
                {
                    unsafe {
                        TRIE_STATS.write().delta_enc[*(node_head as *mut u8).add(size_of::<NodeHeader>()) as usize] += 1;
                    }
                }

                if !handle_report_sub_node(node_head, rqc, cb) {
                    return OK;
                }
                tree_ctx.offset += get_offset_sub_node_non_delta(node_head);
                log_range(&format!("update4: {}", tree_ctx.offset));
            }

            if tree_ctx.offset >= (data_end as usize) {
                break;
            }
        }
    }

    KeyNotFound
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn range_find_first_embedded(rqc: &mut RangeQueryContext, cb: HyperionCallback, container: *mut EmbeddedContainer) -> ReturnCode {
    log_range("range_find_first_embedded");
    #[cfg(feature = "triestats")]
    {
        TRIE_STATS.write().num_embedded_container += 1;
    }

    let mut inscope_top = 0;
    let mut ends_here = false;
    let mut look_for_sub: *mut u8 = null_mut();
    let look_for_top: *mut u8 = unsafe { rqc.key_begin.add(rqc.current_key_offset as usize) };

    if rqc.current_key_offset >= rqc.key_len - 2 {
        ends_here = true;
    }

    if rqc.current_key_offset != rqc.key_len - 1 {
        look_for_sub = unsafe { rqc.key_begin.add(rqc.current_key_offset as usize + 1) };
    }

    let top = unsafe { rqc.current_key.add(rqc.current_key_offset as usize) };
    let sub = unsafe { rqc.current_key.add(rqc.current_key_offset as usize + 1) };
    unsafe {
        *top = 0;
    }

    let mut embedded_offset = size_of::<EmbeddedContainer>();
    let mut jump_point = NoJump;

    loop {
        let node_head = unsafe { (container as *mut u8).add(embedded_offset) as *mut NodeHeader };
        match jump_point {
            NoJump => {
                #[cfg(feature = "triestats")]
                {
                    TRIE_STATS.write().num_internal_nodes += 1;
                    if as_top_node(node_head).delta() > 0 {
                        TRIE_STATS.write().num_delta_encoded += 1;
                    }
                }

                if as_top_node(node_head).container_type() == NodeState::TopNode {
                    unsafe {
                        log_range(&format!("current top: {}", unsafe { *top }));
                        *top = if as_top_node(node_head).delta() != 0 {
                            as_top_node(node_head).delta()
                        } else {
                            *(node_head as *mut u8).add(size_of::<NodeHeader>())
                        };
                        log_range(&format!("set top to: {}", *top));
                    }

                    #[cfg(feature = "triestats")]
                    {
                        let x: i32 = if as_top_node(node_head).delta() != 0 {
                            as_top_node(node_head).delta() as i32
                        } else {
                            unsafe { *(node_head as *mut u8).add(size_of::<NodeHeader>()) as i32 }
                        };
                        TRIE_STATS.write().delta_enc[x as usize] += 1;
                    }

                    if unsafe { *top == *look_for_top } {
                        if ends_here && look_for_sub.is_null() {
                            rqc.do_report = 1;
                        }
                        inscope_top = 1;
                    } else if unsafe { *top > *look_for_top } {
                        rqc.do_report = 1;
                    }

                    if rqc.do_report == 1 && !call_top_node(node_head, rqc, cb) {
                        return OK;
                    }
                    embedded_offset += get_offset_top_node(node_head);
                    log_range(&format!("update1: {}", embedded_offset));
                    unsafe {
                        *sub = 0;
                    }
                } else {
                    unsafe {
                        log_range(&format!("current sub: {}", unsafe { *sub }));
                        *sub = if as_sub_node(node_head).delta() != 0 {
                            as_sub_node(node_head).delta()
                        } else {
                            *(node_head as *mut u8).add(size_of::<NodeHeader>())
                        };
                        log_range(&format!("set sub to: {}", *sub));
                    }

                    #[cfg(feature = "triestats")]
                    {
                        let x: i32 = if as_sub_node(node_head).delta() != 0 {
                            as_sub_node(node_head).delta() as i32
                        } else {
                            unsafe { *(node_head as *mut u8).add(size_of::<NodeHeader>()) as i32 }
                        };
                        TRIE_STATS.write().delta_enc[x as usize] += 1;
                    }

                    if rqc.do_report == 0 {
                        if inscope_top != 0 {
                            if unsafe { *sub == *look_for_sub } {
                                if ends_here {
                                    rqc.do_report = 1;
                                    jump_point = JumpPoint1;
                                    continue;
                                }

                                match as_sub_node(node_head).child_container() {
                                    Link => {
                                        rqc.current_stack_depth += 1;
                                        rqc.current_key_offset += 2;

                                        if rqc.stack[rqc.current_stack_depth as usize].is_none() {
                                            rqc.stack[rqc.current_stack_depth as usize] = Some(TraversalContext {
                                                offset: 0,
                                                hyperion_pointer: HyperionPointer::default(),
                                            });
                                        }

                                        unsafe {
                                            let src =
                                                (*((node_head as *mut u8).add(get_offset_child_container(node_head)) as *mut ContainerLink)).ptr;
                                            if let Some(ref mut context) = rqc.stack[rqc.current_stack_depth as usize] {
                                                context.hyperion_pointer = src;
                                            }
                                        }
                                        let tree_ctx = &mut rqc.stack[rqc.current_stack_depth as usize].expect(ERR_NO_VALUE);
                                        tree_ctx.offset = 0;

                                        if range_find_first_container(rqc, cb) == OK {
                                            return OK;
                                        }
                                        rqc.current_key_offset -= 2;
                                        rqc.current_stack_depth -= 1;
                                    },
                                    ChildLinkType::EmbeddedContainer => {
                                        rqc.current_key_offset += 2;
                                        let emb_head =
                                            unsafe { (node_head as *mut u8).add(get_offset_child_container(node_head)) as *mut EmbeddedContainer };

                                        if range_find_first_embedded(rqc, cb, emb_head) == OK {
                                            return OK;
                                        }
                                        rqc.current_key_offset -= 2;
                                    },
                                    PathCompressed => {
                                        rqc.current_key_offset += 2;
                                        if check_path_compressed_key(node_head, rqc) >= 0 {
                                            rqc.do_report = 1;
                                            rqc.current_key_offset -= 2;
                                            jump_point = JumpPoint1;
                                            continue;
                                        }
                                        rqc.current_key_offset -= 2;
                                    },
                                    _ => {},
                                }
                            } else if unsafe { *sub > *look_for_sub } {
                                rqc.do_report = 1;
                                jump_point = JumpPoint1;
                                continue;
                            }
                        }
                    } else {
                        jump_point = JumpPoint1;
                        continue;
                    }
                    embedded_offset += get_offset_sub_node(node_head);
                    log_range(&format!("update2: {}", embedded_offset));
                }
            },
            _ => {
                jump_point = NoJump;
                if !handle_report_sub_node(node_head, rqc, cb) {
                    return OK;
                }
            },
        }

        if embedded_offset < unsafe { (*container).size() as usize } {
            break;
        }
    }
    KeyNotFound
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn range_report_embedded(rqc: &mut RangeQueryContext, cb: HyperionCallback, container: *mut EmbeddedContainer) -> ReturnCode {
    log_range("range_report_embedded");
    #[cfg(feature = "triestats")]
    {
        TRIE_STATS.write().num_embedded_container += 1;
    }

    let mut embedded_offset = size_of::<EmbeddedContainer>();
    let top = unsafe { rqc.current_key.add(rqc.current_key_offset as usize) };
    let sub = unsafe { top.add(1) };
    unsafe {
        *top = 0;
    }

    loop {
        let node_head = unsafe { (container as *mut u8).add(embedded_offset) as *mut NodeHeader };

        #[cfg(feature = "triestats")]
        {
            TRIE_STATS.write().num_internal_nodes += 1;
            if as_top_node(node_head).delta() > 0 {
                TRIE_STATS.write().num_delta_encoded += 1;
            }
        }

        if as_top_node(node_head).container_type() == NodeState::TopNode {
            if as_top_node(node_head).delta() == 0 {
                unsafe {
                    *top = *(node_head as *mut u8).add(size_of::<NodeHeader>());
                }

                #[cfg(feature = "triestats")]
                {
                    TRIE_STATS.write().delta_enc[unsafe { *top as usize }] += 1;
                }

                if !call_top_node(node_head, rqc, cb) {
                    return OK;
                }
                embedded_offset += get_offset_top_node_non_delta(node_head);
            } else {
                unsafe {
                    *top += as_top_node(node_head).delta();
                }

                #[cfg(feature = "triestats")]
                {
                    TRIE_STATS.write().delta_enc[as_top_node(node_head).delta() as usize] += 1;
                }

                if !call_top_node(node_head, rqc, cb) {
                    return OK;
                }
                embedded_offset += get_offset_top_node_delta(node_head);
            }
            unsafe {
                *sub = 0;
            }
        } else if as_sub_node(node_head).delta() == 0 {
            unsafe {
                *sub = *(node_head as *mut u8).add(size_of::<NodeHeader>());
            }

            #[cfg(feature = "triestats")]
            {
                TRIE_STATS.write().delta_enc[unsafe { *sub as usize }] += 1;
            }

            if !handle_report_sub_node(node_head, rqc, cb) {
                return OK;
            }
            embedded_offset += get_offset_sub_node_non_delta(node_head);
        } else {
            unsafe {
                *sub = as_sub_node(node_head).delta();
            }

            #[cfg(feature = "triestats")]
            {
                TRIE_STATS.write().delta_enc[as_sub_node(node_head).delta() as usize] += 1;
            }

            if !handle_report_sub_node(node_head, rqc, cb) {
                return OK;
            }
            embedded_offset += get_offset_sub_node_delta(node_head);
        }

        if embedded_offset >= unsafe { (*container).size() as usize } {
            break;
        }
    }
    KeyNotFound
}

pub fn check_path_compressed_key(node_head: *mut NodeHeader, rqc: &mut RangeQueryContext) -> i32 {
    log_range("check_path_compressed_key");
    let mut tmp_key: [u8; 128] = [0; 128];
    let pc_key_size;
    let pc_key: *mut u8;

    let pc_head = as_raw_compressed_mut(node_head);

    unsafe {
        if (*pc_head).value_present() {
            pc_key = (pc_head as *mut u8).add(size_of::<PathCompressedNodeHeader>() + size_of::<NodeValue>());
            pc_key_size = (*pc_head).size() - (size_of::<PathCompressedNodeHeader>() + size_of::<NodeValue>());
        } else {
            pc_key = (pc_head as *mut u8).add(size_of::<PathCompressedNodeHeader>());
            pc_key_size = (*pc_head).size() - size_of::<PathCompressedNodeHeader>();
        }
    }

    #[cfg(feature = "triestats")]
    {
        TRIE_STATS.write().path_compressed[pc_key_size] += 1;
    }

    let current_key_len = pc_key_size as i32 + rqc.current_key_offset as i32;

    unsafe {
        copy_nonoverlapping(rqc.key_begin, tmp_key.as_mut_ptr(), rqc.current_key_offset as usize);
        copy_nonoverlapping(pc_key, tmp_key.as_mut_ptr().add(rqc.current_key_offset as usize), pc_key_size);

        if rqc.key_len as i32 <= current_key_len {
            let ret = memcmp(tmp_key.as_mut_ptr() as *mut c_void, rqc.key_begin as *mut c_void, rqc.key_len as size_t);
            if ret < -1 {
                return -1;
            }
            ret
        } else {
            let ret = memcmp(tmp_key.as_mut_ptr() as *mut c_void, rqc.key_begin as *mut c_void, current_key_len as size_t);
            if ret <= 0 {
                return -1;
            }
            ret
        }
    }
}

enum RangeJumpLabels {
    Outer,
    Inner,
    Jump,
    Report,
}

pub fn range_find_first_container(rqc: &mut RangeQueryContext, cb: HyperionCallback) -> ReturnCode {
    log_range("range_find_first_container");
    let mut inscope_top = 0;
    let mut ends_here = false;
    let mut look_for_sub: *mut u8 = null_mut();
    let look_for_top: *mut u8 = unsafe { rqc.key_begin.add(rqc.current_key_offset as usize) };

    let mut node_head: *mut NodeHeader = null_mut();

    if rqc.current_key_offset >= rqc.key_len.wrapping_sub(2) {
        ends_here = true;
    }

    if rqc.current_key_offset != rqc.key_len - 1 {
        look_for_sub = unsafe { rqc.key_begin.add(rqc.current_key_offset as usize + 1) };
    }

    let top = unsafe { rqc.current_key.add(rqc.current_key_offset as usize) };
    let sub = unsafe { rqc.current_key.add(rqc.current_key_offset as usize + 1) };

    let mut segment_chain = SegmentChain::default();

    let tree_ctx = &mut rqc.stack[rqc.current_stack_depth as usize].expect(ERR_NO_VALUE);
    let element_count: usize = if tree_ctx.hyperion_pointer.superbin_id() == 0 {
        get_all_chained_pointer(&mut segment_chain, rqc.arena, &mut tree_ctx.hyperion_pointer) as usize
    } else {
        segment_chain.pointer[0].store(get_pointer(rqc.arena, &mut tree_ctx.hyperion_pointer, 0, 0));
        1
    };

    let mut jump_point = RangeJumpLabels::Outer;
    let mut i = 0;
    let mut jump = true;

    'outer: loop {
        if jump {
            jump = false;
        } else {
            i += 1;
            jump_point = RangeJumpLabels::Outer;
        }
        if i >= element_count {
            break;
        }
        let container = segment_chain.pointer[i].get() as *mut Container;

        match jump_point {
            RangeJumpLabels::Outer => {
                stats_container(container);

                unsafe { *top = segment_chain.chars[i] };

                if unsafe { (*container).jump_table() == 0 } {
                    tree_ctx.offset = get_container_head_size();
                } else {
                    unsafe {
                        *top = (*container).get_key_and_offset_with_jump_table(*look_for_top, &mut tree_ctx.offset);
                        node_head = (container as *mut u8).add(tree_ctx.offset) as *mut NodeHeader;
                        jump_point = RangeJumpLabels::Jump;
                        jump = true;
                        continue;
                    }
                }
                jump_point = RangeJumpLabels::Inner;
                jump = true;
                continue;
            },
            RangeJumpLabels::Inner => loop {
                jump_point = RangeJumpLabels::Inner;
                node_head = unsafe { (container as *mut u8).add(tree_ctx.offset) as *mut NodeHeader };

                if as_top_node(node_head).container_type() == NodeState::TopNode {
                    if as_top_node(node_head).type_flag() == Invalid {
                        break;
                    }

                    unsafe {
                        *sub = 0;
                        *top += if as_top_node(node_head).delta() != 0 {
                            as_top_node(node_head).delta()
                        } else {
                            *((node_head as *mut u8).add(size_of::<NodeHeader>()))
                        };
                    }

                    jump_point = RangeJumpLabels::Jump;
                    jump = true;
                    continue 'outer;
                } else {
                    unsafe {
                        *sub += if as_sub_node(node_head).delta() != 0 {
                            as_sub_node(node_head).delta()
                        } else {
                            *((node_head as *mut u8).add(size_of::<NodeHeader>()))
                        };
                    }

                    if rqc.do_report == 0 {
                        if inscope_top != 0 {
                            if unsafe { *sub == *look_for_sub } {
                                if ends_here {
                                    rqc.do_report = 1;
                                    jump_point = RangeJumpLabels::Report;
                                    jump = true;
                                    continue 'outer;
                                }

                                match as_sub_node(node_head).child_container() {
                                    Link => {
                                        rqc.current_stack_depth += 1;
                                        rqc.current_key_offset += 2;
                                        if rqc.stack[rqc.current_stack_depth as usize].is_none() {
                                            rqc.stack[rqc.current_stack_depth as usize] = Some(TraversalContext {
                                                offset: 0,
                                                hyperion_pointer: HyperionPointer::default(),
                                            });
                                        }

                                        unsafe {
                                            let src =
                                                (*((node_head as *mut u8).add(get_offset_child_container(node_head)) as *mut ContainerLink)).ptr;
                                            if let Some(ref mut context) = rqc.stack[rqc.current_stack_depth as usize] {
                                                context.hyperion_pointer = src;
                                            }
                                        }
                                        tree_ctx.offset = 0;

                                        if range_find_first_container(rqc, cb) == OK {
                                            return OK;
                                        }
                                        rqc.current_key_offset -= 2;
                                        rqc.current_stack_depth -= 1;
                                    },
                                    ChildLinkType::EmbeddedContainer => {
                                        rqc.current_key_offset += 2;
                                        let emb_head =
                                            unsafe { (node_head as *mut u8).add(get_offset_child_container(node_head)) as *mut EmbeddedContainer };

                                        if range_find_first_embedded(rqc, cb, emb_head) == OK {
                                            return OK;
                                        }
                                        rqc.current_key_offset -= 2;
                                    },
                                    PathCompressed => {
                                        rqc.current_key_offset += 2;
                                        if check_path_compressed_key(node_head, rqc) >= 0 {
                                            rqc.do_report = 1;
                                            rqc.current_key_offset -= 2;
                                            jump_point = RangeJumpLabels::Report;
                                            jump = true;
                                            continue 'outer;
                                        }
                                        rqc.current_key_offset -= 2;
                                    },
                                    _ => {},
                                }
                            } else if unsafe { *sub > *look_for_sub } {
                                rqc.do_report = 1;
                                jump_point = RangeJumpLabels::Report;
                                jump = true;
                                continue 'outer;
                            }
                        }
                    } else {
                        jump_point = RangeJumpLabels::Report;
                        jump = true;
                        continue 'outer;
                    }
                }

                if tree_ctx.offset >= unsafe { (*container).size() as usize } {
                    break;
                }
            },
            RangeJumpLabels::Jump => {
                if unsafe { *top == *look_for_top } {
                    if ends_here && look_for_sub.is_null() {
                        rqc.do_report = 1;
                    }
                    inscope_top = 1;
                } else if unsafe { *top > *look_for_top } {
                    rqc.do_report = 1;
                }

                if rqc.do_report == 1 && !call_top_node(node_head, rqc, cb) {
                    return OK;
                }
                tree_ctx.offset += get_offset_top_node(node_head);

                if tree_ctx.offset >= unsafe { (*container).size() as usize } {
                    break;
                }
                jump_point = RangeJumpLabels::Inner;
                jump = true;
            },
            RangeJumpLabels::Report => {
                jump_point = RangeJumpLabels::Inner;
                jump = false;
                if !handle_report_sub_node(node_head, rqc, cb) {
                    return OK;
                }
                tree_ctx.offset += get_offset_sub_node(node_head);
                if tree_ctx.offset >= unsafe { (*container).size() as usize } {
                    break;
                }
            },
        }
    }
    KeyNotFound
}

pub fn handle_report_sub_node(node_head: *mut NodeHeader, rqc: &mut RangeQueryContext, cb: HyperionCallback) -> bool {
    log_range("handle_report_sub_node");
    if !call_sub_node(node_head, rqc, cb) {
        return false;
    }

    match as_sub_node(node_head).child_container() {
        Link => {
            rqc.current_stack_depth += 1;
            rqc.current_key_offset += 2;

            if rqc.stack[rqc.current_stack_depth as usize].is_none() {
                rqc.stack[rqc.current_stack_depth as usize] = Some(TraversalContext {
                    offset: 0,
                    hyperion_pointer: HyperionPointer::default(),
                });
            }

            unsafe {
                let src = (*((node_head as *mut u8).add(get_offset_child_container(node_head)) as *mut ContainerLink)).ptr;
                if let Some(ref mut context) = rqc.stack[rqc.current_stack_depth as usize] {
                    context.hyperion_pointer = src;
                }
            }
            if range_report_container(rqc, cb) == OK {
                return false;
            }
            rqc.current_key_offset -= 2;
            rqc.current_stack_depth -= 1;
            return true;
        },
        ChildLinkType::EmbeddedContainer => {
            rqc.current_key_offset += 2;
            let container = unsafe { (node_head as *mut u8).add(get_offset_child_container(node_head)) as *mut EmbeddedContainer };
            if range_report_embedded(rqc, cb, container) == OK {
                return false;
            }
            rqc.current_key_offset -= 2;
            return true;
        },
        PathCompressed => {
            let pc_key_size;
            let pc_key: *mut u8;
            let pc_head = as_raw_compressed_mut(node_head);
            let value: *mut NodeValue;
            let sub = unsafe { rqc.current_key.add(rqc.current_key_offset as usize + 1) };

            if unsafe { (*pc_head).value_present() } {
                pc_key = unsafe { (pc_head as *mut u8).add(size_of::<PathCompressedNodeHeader>() + size_of::<NodeValue>()) };
                value = unsafe { pc_head.add(1) as *mut NodeValue };
                pc_key_size = unsafe { (*pc_head).size() - (size_of::<PathCompressedNodeHeader>() + size_of::<NodeValue>()) };
            } else {
                pc_key = unsafe { (pc_head as *mut u8).add(size_of::<PathCompressedNodeHeader>()) };
                pc_key_size = unsafe { (*pc_head).size() - size_of::<PathCompressedNodeHeader>() };
                value = null_mut();
            }

            #[cfg(feature = "triestats")]
            {
                TRIE_STATS.write().path_compressed[pc_key_size] += 1;
            }

            unsafe {
                copy_nonoverlapping(pc_key, sub.add(1), pc_key_size);
            }
            rqc.traversed_leaves += 1;
            return cb(rqc.current_key, rqc.current_key_offset as u16 + pc_key_size as u16 + 2, value as *mut u8);
        },
        _ => {},
    }
    true
}

pub fn initialize_operation_context(
    ocx: &mut OperationContext, operation_command: OperationCommand, root_container_entry: &mut RootContainerEntryInner, key: *mut u8, key_len: u16,
) {
    ocx.header.set_command(operation_command);
    ocx.header.set_next_container_valid(ContainerValid);
    ocx.root_container_entry = Some(root_container_entry as *mut RootContainerEntryInner);
    ocx.arena = Some(root_container_entry.arena.unwrap());
    if let Some(ref mut hyperion_pointer) = root_container_entry.hyperion_pointer {
        ocx.next_container_pointer = Some(hyperion_pointer as *mut HyperionPointer);
    }
    //ocx.next_container_pointer = Some(&mut root_container_entry.hyperion_pointer.unwrap() as *mut HyperionPointer);
    ocx.key = Some(key);
    ocx.key_len_left = key_len as i32;
}

pub fn put_debug(
    arena: *mut Arena, container_pointer: &mut HyperionPointer, key: &mut u8, key_len: u32, node_value: Option<*mut NodeValue>,
) -> ReturnCode {
    let mut operation_context: OperationContext = OperationContext {
        key_len_left: key_len as i32,
        key: Some(key as *mut u8),
        next_container_pointer: Some(container_pointer as *mut HyperionPointer),
        arena: Some(arena),
        input_value: node_value,
        ..OperationContext::default()
    };
    operation_context.header.set_command(Put);
    operation_context.header.set_next_container_valid(ContainerValid);
    traverse_tree(&mut operation_context)
}

pub fn int_range(root_container_entry: &mut RootContainerEntryInner, key: *mut u8, key_len: u16, hyperion_callback: HyperionCallback) -> ReturnCode {
    let mut tmp_key: [u8; 4096] = [0; 4096];
    let mut rqc: RangeQueryContext = RangeQueryContext {
        key_begin: key,
        current_key: tmp_key.as_mut_ptr(),
        arena: root_container_entry.arena.unwrap(),
        current_stack_depth: 0,
        current_key_offset: 0,
        key_len: key_len as i16,
        do_report: 0,
        traversed_leaves: 0,
        stack: [None; 128],
    };
    rqc.stack[0] = Some(TraversalContext {
        offset: 0,
        hyperion_pointer: root_container_entry.hyperion_pointer.unwrap(),
    });

    range_find_first_container(&mut rqc, hyperion_callback);
    root_container_entry.stats.range_queries += 1;
    root_container_entry.stats.range_queries_leaves = rqc.traversed_leaves;
    OK
}

pub fn int_get(root_container_entry: &mut RootContainerEntryInner, key: *mut u8, key_len: u16, return_value: *mut NodeValue) -> ReturnCode {
    let mut ocx = OperationContext::default();
    initialize_operation_context(&mut ocx, Get, root_container_entry, key, key_len);
    ocx.return_value = Some(return_value);
    let ret = traverse_tree(&mut ocx);
    unsafe { (*(ocx.root_container_entry.unwrap())).stats.gets += 1 };
    ret
}

pub fn int_put(root_container_entry: &mut RootContainerEntryInner, key: *mut u8, key_len: u16, return_value: Option<*mut NodeValue>) -> ReturnCode {
    let mut ocx = OperationContext::default();
    initialize_operation_context(&mut ocx, Put, root_container_entry, key, key_len);
    ocx.input_value = return_value;
    let ret = traverse_tree(&mut ocx);
    if ocx.header.performed_put() {
        unsafe { (*(ocx.root_container_entry.unwrap())).stats.puts += 1 };
    } else {
        unsafe { (*(ocx.root_container_entry.unwrap())).stats.updates += 1 };
    }
    ret
}

pub fn remove(root_container_entry: &mut RootContainerEntryInner, key: *mut u8, key_len: u16) -> ReturnCode {
    let mut ocx = OperationContext::default();
    initialize_operation_context(&mut ocx, Delete, root_container_entry, key, key_len);
    let ret = traverse_tree(&mut ocx);
    unsafe { (*(ocx.root_container_entry.unwrap())).stats.puts += 1 };
    ret
}

use crate::hyperion::components::path_compressed_header::PathCompressedNodeHeader;
use std::io::Write;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize};

const LOG: bool = false;
static FD: AtomicUsize = AtomicUsize::new(0);
static CURRENT_LINES: AtomicU64 = AtomicU64::new(0);
static DELETE_OLD_LOGS: AtomicBool = AtomicBool::new(true);

pub fn delete_log_files() -> io::Result<()> {
    for entry in fs::read_dir(".")? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                if ext == "log" {
                    fs::remove_file(&path)?;
                }
            }
        }
    }
    Ok(())
}

pub fn log_to_file(message: &str) {
    if DELETE_OLD_LOGS.load(Relaxed) {
        DELETE_OLD_LOGS.store(false, Relaxed);
        delete_log_files().expect("Cannot delete log files");
    }

    if CURRENT_LINES.load(Relaxed) >= 50000 {
        FD.fetch_add(1, Relaxed);
        CURRENT_LINES.store(0, Relaxed);
    }

    if !LOG {
        return;
    }
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(format!("debug{}.log", FD.load(Relaxed))) {
        let _ = writeln!(file, "{}", message);
        let _ = file.flush();
        CURRENT_LINES.store(CURRENT_LINES.load(Relaxed) + 1, Relaxed);
    } else {
        eprintln!("Fehler beim Öffnen der Log-Datei");
    }
}

static LOG_RANGE: bool = false;

pub fn log_range(message: &str) {
    if DELETE_OLD_LOGS.load(Relaxed) {
        DELETE_OLD_LOGS.store(false, Relaxed);
        delete_log_files().expect("Cannot delete log files");
    }

    if CURRENT_LINES.load(Relaxed) >= 50000 {
        FD.fetch_add(1, Relaxed);
        CURRENT_LINES.store(0, Relaxed);
    }

    if !LOG_RANGE {
        return;
    }
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(format!("debug{}.log", FD.load(Relaxed))) {
        let _ = writeln!(file, "{}", message);
        let _ = file.flush();
        CURRENT_LINES.store(CURRENT_LINES.load(Relaxed) + 1, Relaxed);
    } else {
        eprintln!("Fehler beim Öffnen der Log-Datei");
    }
}
