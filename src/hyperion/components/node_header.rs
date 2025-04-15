use std::arch::x86_64::{_mm_prefetch, _MM_HINT_T0};
use crate::hyperion::components::container::{
    get_container_head_size, get_container_link_size, initialize_container, shift_container, update_space, wrap_shift_container, Container,
    ContainerLink, EmbeddedContainer, CONTAINER_MAX_EMBEDDED_DEPTH, CONTAINER_MAX_FREE_BYTES,
};
use crate::hyperion::components::context::OperationCommand::Put;
use crate::hyperion::components::context::{
    ContainerTraversalContext, JumpContext, PathCompressedEjectionContext, RangeQueryContext, DELTA_MAX_VALUE,
};
use crate::hyperion::components::jump_table::{TopNodeJumpTable, TOP_NODE_JUMP_TABLE_ENTRIES, TOP_NODE_JUMP_TABLE_SHIFT};
use crate::hyperion::components::node::NodeType::{InnerNode, Invalid, LeafNodeEmpty, LeafNodeWithValue};
use crate::hyperion::components::node::{get_sub_node_key, set_nodes_key, update_successor_key, Node, NodeState, NodeValue};
use crate::hyperion::components::node_header::EmbedLinkCommands::{
    CreateEmbeddedContainer, CreateLinkToContainer, CreatePathCompressedNode, TransformPathCompressedNode,
};
use crate::hyperion::components::operation_context::ContainerValidTypes::{ContainerValid, EmbeddedContainerValid};
use crate::hyperion::components::operation_context::{
    meta_expand, new_expand, new_expand_embedded, safe_top_node_jump_context, ContainerValidTypes, OperationContext,
};
use crate::hyperion::components::path_compressed_header::PathCompressedNodeHeader;
use crate::hyperion::components::return_codes::ReturnCode;
use crate::hyperion::components::return_codes::ReturnCode::{ChildContainerMissing, GetFailureNoLeaf, OK};
use crate::hyperion::components::sub_node::ChildLinkType::{Link, PathCompressed};
use crate::hyperion::components::sub_node::{ChildLinkType, SubNode};
use crate::hyperion::components::top_node::TopNode;
use crate::hyperion::internals::atomic_pointer::AtomicEmbContainer;
use crate::hyperion::internals::core::{initialize_ejected_container, log_to_file, HyperionCallback, GLOBAL_CONFIG};
use crate::hyperion::internals::errors::{
    ERR_EMPTY_EMB_STACK, ERR_EMPTY_EMB_STACK_POS, ERR_NO_CAST_MUT_REF, ERR_NO_CAST_REF, ERR_NO_INPUT_VALUE, ERR_NO_NEXT_CONTAINER, ERR_NO_POINTER,
    ERR_NO_SUCCESSOR,
};
use crate::memorymanager::api::{get_pointer, reallocate, HyperionPointer};
use std::cmp::Ordering;
use std::ptr::{copy, copy_nonoverlapping, null_mut, read_unaligned, write_bytes, write_unaligned, NonNull};

pub const MAX_KEY_LENGTH_PATH_COMPRESSION: i32 = 128;

#[repr(C)]
#[derive(Clone, Copy)]
union NodeUnion {
    pub top_node: TopNode,
    pub sub_node: SubNode,
}

/// Safe wrapper for a union, storing either a top node header or a sub node header.
#[repr(C)]
pub struct NodeHeader {
    header: NodeUnion,
}

impl NodeHeader {
    /// Creates a new NodeHeader with the given TopNode.
    pub fn new_top_node(top_node: TopNode) -> Self {
        NodeHeader {
            header: NodeUnion { top_node },
        }
    }

    /// Creates a new NodeHeader with the given SubNode.
    pub fn new_sub_node(sub_node: SubNode) -> Self {
        NodeHeader {
            header: NodeUnion { sub_node },
        }
    }
}

/// Returns the node header as a path compressed node header.
/// # Safety
/// - `node_head` must be a valid, aligned pointer for reading and writing.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn as_raw_compressed(node_head: *mut NodeHeader) -> *const PathCompressedNodeHeader {
    unsafe { node_head.add(get_offset_child_container(node_head)) as *const PathCompressedNodeHeader }
}

/// Returns the node header as a mutable path compressed node header.
/// # Safety
/// - `node_head` must be a valid, aligned pointer for reading and writing.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn as_raw_compressed_mut(node_head: *mut NodeHeader) -> *mut PathCompressedNodeHeader {
    unsafe { node_head.add(get_offset_child_container(node_head)) as *mut PathCompressedNodeHeader }
}

/// Returns the node header as a reference to a path compressed node header.
/// # Safety
/// - `node_head` must be a valid, aligned pointer for reading and writing.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn as_path_compressed<'a>(node_head: *mut NodeHeader) -> &'a PathCompressedNodeHeader {
    unsafe { as_raw_compressed(node_head).as_ref().expect(ERR_NO_CAST_REF) }
}

/// Returns the node header as a mutable reference to a path compressed node header.
/// # Safety
/// - `node_head` must be a valid, aligned pointer for reading and writing.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn as_path_compressed_mut<'a>(node_head: *mut NodeHeader) -> &'a mut PathCompressedNodeHeader {
    unsafe { as_raw_compressed_mut(node_head).as_mut().expect(ERR_NO_CAST_MUT_REF) }
}

/// Returns the node header as a mutable embedded container.
/// # Safety
/// - `node_head` must be a valid, aligned pointer for reading and writing.
/// - `node_head + offset` must be in a valid memory region.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn as_raw_embedded(node_head: *mut NodeHeader, offset: usize) -> *const EmbeddedContainer {
    unsafe { node_head.add(offset) as *const EmbeddedContainer }
}

/// Returns the specified node header as a mutable reference to a [`TopNode`].
/// # Safety
/// - `node_head` must be a valid, aligned pointer for reading and writing.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn as_top_node_mut<'a>(node_head: *mut NodeHeader) -> &'a mut TopNode {
    unsafe { &mut (*node_head).header.top_node }
}

/// Returns the specified node header as a reference to a [`TopNode`].
/// # Safety
/// - `node_head` must be a valid, aligned pointer for reading and writing.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn as_top_node<'a>(node_head: *mut NodeHeader) -> &'a TopNode {
    unsafe { &((*node_head).header.top_node) }
}

/// Returns the specified node header as a mutable reference to a [`SubNode`].
/// # Safety
/// - `node_head` must be a valid, aligned pointer for reading and writing.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn as_sub_node_mut<'a>(node_head: *mut NodeHeader) -> &'a mut SubNode {
    unsafe { &mut (*node_head).header.sub_node }
}

/// Returns the specified node header as a reference to a [`SubNode`].
/// # Safety
/// - `node_head` must be a valid, aligned pointer for reading and writing.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn as_sub_node<'a>(node_head: *mut NodeHeader) -> &'a SubNode {
    unsafe { &(*node_head).header.sub_node }
}

/// Returns the overhead introduced to `node_head` by the node's jump table and jump successor.
/// # Safety
/// This function is intended for use on [`TopNode`]. Calling this function on a [`SubNode`] will result in undefined behavior.
#[inline]
pub fn get_jump_overhead(node_head: *mut NodeHeader) -> usize {
    let top_node: &TopNode = as_top_node(node_head);
    top_node.jump_successor_present() as usize * size_of::<u16>() + top_node.jump_table_present() as usize * size_of::<TopNodeJumpTable>()
}

/// Returns the size of the leaf node value stored in `node_head`.
///
/// If `node_head` is not a leaf node, returns 0.
#[inline]
pub fn get_leaf_size(node_head: *mut NodeHeader) -> usize {
    match as_top_node(node_head).type_flag() {
        LeafNodeWithValue => size_of::<NodeValue>(),
        _ => 0,
    }
}

/// Returns the offset of the child container to this [`SubNode`].
///
/// Non-delta encoded nodes have an offset of their header's size plus their key's size plus their leaf size. Delta-encoded nodes save 1 byte offset
/// by encoding the key into the node's header.
/// # Safety
/// This function is intended for use on [`SubNode`]. Calling this function on a [`TopNode`] will result in undefined behavior.
#[inline]
pub fn get_offset_child_container(node_head: *mut NodeHeader) -> usize {
    let base_size: usize = size_of::<NodeHeader>() + get_leaf_size(node_head);
    base_size + if as_top_node(node_head).delta() == 0 { 1 } else { 0 }
}

/// Returns the size of the child link in `node_head`.
///
/// # Returns
/// - If the node has no child link, returns 0.
/// - If the node has a link to another container, returns the size of a `ContainerLink`.
/// - If the node has an embedded container, returns the size of an `EmbeddedContainer`.
/// - If the node is path compressed, returns the size of a `PathCompressedNodeHeader`.
/// # Safety
/// This function is intended for use on [`SubNode`]. Calling this function on a [`TopNode`] will result in undefined behavior.
#[inline]
pub fn get_child_link_size(node_head: *mut NodeHeader) -> usize {
    match as_sub_node(node_head).child_container() {
        ChildLinkType::None => 0,
        Link => size_of::<ContainerLink>(),
        ChildLinkType::EmbeddedContainer => {
            // log_to_file("Child link: Embedded container");
            unsafe { (*((node_head as *mut u8).add(get_offset_child_container(node_head)) as *mut EmbeddedContainer)).size() as usize }
        },
        PathCompressed => {
            // log_to_file("Child link: Path compressed");
            unsafe { (*(as_raw_compressed(node_head))).size() }
        },
    }
}

/// Returns the offset of the next node starting at this node.
#[inline]
pub fn get_offset(node_head: *mut NodeHeader) -> usize {
    match as_top_node(node_head).container_type() {
        NodeState::TopNode => get_offset_top_node(node_head),
        NodeState::SubNode => get_offset_sub_node(node_head),
    }
}

/// Returns the offset of the next node starting at this [`TopNode`].
/// # Safety
/// This function is intended for use on [`TopNode`]. Calling this function on a [`SubNode`] will result in undefined behavior.
#[inline]
pub fn get_offset_top_node(node_head: *mut NodeHeader) -> usize {
    match as_top_node(node_head).has_delta() {
        false => get_offset_top_node_non_delta(node_head),
        true => get_offset_top_node_delta(node_head),
    }
}

/// Returns the offset of the next node starting at this delta encoded [`TopNode`].
///
/// This function does not check if the node is delta encoded. See [`get_offset_top_node`] if it cannot be ensured that
/// the node is delta encoded.
/// # Safety
/// This function is intended for use on [`TopNode`]. Calling this function on a [`SubNode`] will result in undefined behavior.
#[inline]
pub fn get_offset_top_node_delta(node_head: *mut NodeHeader) -> usize {
    size_of::<NodeHeader>() + get_jump_overhead(node_head) + get_leaf_size(node_head)
}

/// Returns the offset of the next node starting at this non-delta encoded [`TopNode`].
///
/// This function does not check if the node is delta encoded. See [`get_offset_top_node`] if it cannot be ensured that
/// the node is non-delta encoded.
/// # Safety
/// This function is intended for use on [`TopNode`]. Calling this function on a [`SubNode`] will result in undefined behavior.
#[inline]
pub fn get_offset_top_node_non_delta(node_head: *mut NodeHeader) -> usize {
    get_offset_top_node_delta(node_head) + 1
}

/// Returns the offset of the next node starting at this [`SubNode`].
/// # Safety
/// This function is intended for use on [`SubNode`]. Calling this function on a [`TopNode`] will result in undefined behavior.
#[inline]
pub fn get_offset_sub_node(node_head: *mut NodeHeader) -> usize {
    let base_size: usize = size_of::<NodeHeader>() + get_leaf_size(node_head) + get_child_link_size(node_head);
    base_size + if as_top_node(node_head).delta() == 0 { 1 } else { 0 }
}

/// Returns the offset of the next node starting at this delta encoded [`SubNode`].
/// # Safety
/// This function is intended for use on [`SubNode`]. Calling this function on a [`TopNode`] will result in undefined behavior.
#[inline]
pub fn get_offset_sub_node_delta(node_head: *mut NodeHeader) -> usize {
    size_of::<NodeHeader>() + get_leaf_size(node_head) + get_child_link_size(node_head)
}

/// Returns the offset of the next node starting at this non-delta encoded [`SubNode`].
/// # Safety
/// This function is intended for use on [`SubNode`]. Calling this function on a [`TopNode`] will result in undefined behavior.
#[inline]
pub fn get_offset_sub_node_non_delta(node_head: *mut NodeHeader) -> usize {
    get_offset_sub_node_delta(node_head) + size_of::<u8>()
}

/// Returns the offset of the node's value from the node's base address.
#[inline]
pub fn get_offset_node_value(node_head: *mut NodeHeader) -> usize {
    let top_node: &TopNode = as_top_node(node_head);
    let mut base_size: usize = size_of::<NodeHeader>();

    if top_node.delta() == 0 {
        base_size += 1;
    }

    if top_node.container_type() == NodeState::TopNode {
        return base_size + get_jump_overhead(node_head);
    }
    base_size
}

/// Returns the offset of the node's jump successor from the node's base address.
/// # Safety
/// This function is intended for use on [`TopNode`]. Calling this function on a [`SubNode`] will result in undefined behavior.
#[inline]
pub fn get_offset_jump_successor(node_head: *mut NodeHeader) -> usize {
    let base_size: usize = size_of::<NodeHeader>();
    base_size + if as_top_node(node_head).delta() == 0 { 1 } else { 0 }
}

/// Returns the jump value of the top node's jump successor.
///
/// # Returns
/// - A 16 bit offset to the node's sibling top node.
/// # Safety
/// This function is intended for use on [`TopNode`]. Calling this function on a [`SubNode`] will result in undefined behavior.
/// - `node_head` must be a valid, aligned pointer for reading and writing.
#[inline]
pub fn get_jump_successor_value(node_head: *mut NodeHeader) -> usize {
    unsafe { read_unaligned((node_head as *mut u8).add(get_offset_jump_successor(node_head)) as *const u16) as usize }
}

/// Returns the offset of the top node's jump table
/// # Safety
/// This function is intended for use on [`TopNode`]. Calling this function on a [`SubNode`] will result in undefined behavior.
#[inline]
pub fn get_offset_jump_table(node_head: *mut NodeHeader) -> usize {
    get_offset_jump_successor(node_head) + as_top_node(node_head).jump_successor_present() as usize * size_of::<u16>()
}

/// Copies the path compressed node's value into the return value field of the [`OperationContext`].
fn get_node_value_pc(node_head: *mut NodeHeader, ocx: &mut OperationContext) -> ReturnCode {
    // log_to_file("get_node_value_pc");
    let pc_head: &PathCompressedNodeHeader = as_path_compressed(node_head);
    if pc_head.value_present() {
        // log_to_file("get_node_value_pc; copy pc value into return_value");
        //log_to_file("pc_head value present; copy value to return_value");
        if let Some(return_value) = ocx.return_value {
            unsafe {
                copy_nonoverlapping(
                    pc_head.as_raw_char().add(size_of::<PathCompressedNodeHeader>()),
                    return_value.as_ptr() as *mut u8,
                    size_of::<NodeValue>(),
                );
            }
        }
    }
    ocx.header.set_operation_done(true);
    OK
}

/// Checks if the node has some value stored. If some value is stored, this value is copied into the return value field of the [`OperationContext`].
/// # Returns
/// - [`GetFailureNoLeaf`] if the node header is empty or invalid.
/// - [`OK`] if the node header is a leaf node. If the node header belongs to a leaf node with value or a path compressed node, the node value
///   is copied into the return value field of the [`OperationContext`].
/// # Safety
/// - `node_head` must be a valid, aligned pointer for reading and writing.
pub fn get_node_value(node_head: *mut NodeHeader, ocx: &mut OperationContext) -> ReturnCode {
    if ocx.header.pathcompressed_child() {
        return get_node_value_pc(node_head, ocx);
    }

    match as_top_node(node_head).type_flag() {
        LeafNodeEmpty | Invalid => GetFailureNoLeaf,
        LeafNodeWithValue => unsafe {
            copy_nonoverlapping(
                (node_head as *mut u8).add(get_offset_node_value(node_head)),
                ocx.return_value.unwrap().as_ptr() as *mut u8,
                size_of::<NodeValue>(),
            );
            ocx.header.set_operation_done(true);
            OK
        },
        _ => {
            ocx.header.set_operation_done(true);
            OK
        },
    }
}

/// Sets this node's value to the value stored in the input value field of [`OperationContext`].
///
/// If no input value is given, this function creates a leaf node without value (see [`LeafNodeEmpty`]).
/// # Safety
/// - `node_head` must be a valid, aligned pointer for reading and writing.
pub fn set_node_value(node_head: *mut NodeHeader, ocx: &mut OperationContext) {
    let top_node: &mut TopNode = as_top_node_mut(node_head);

    if let Some(input_value) = ocx.input_value {
        if top_node.type_flag() == Invalid || top_node.type_flag() == InnerNode {
            ocx.header.set_performed_put(true);
        }

        unsafe {
            // log_to_file("set_node_value; copy input_value into container");
            // log_to_file(&format!("copy input value of {}", unsafe { (*(input_value.as_ptr())).value }));
            copy_nonoverlapping(
                input_value.as_ptr() as *mut u8,
                (node_head as *mut u8).add(get_offset_node_value(node_head)),
                size_of::<NodeValue>(),
            );
        }
        top_node.set_type_flag(LeafNodeWithValue);
    } else {
        top_node.set_type_flag(LeafNodeEmpty);
    }

    ocx.header.set_operation_done(true);
}

/// Registers a new [`JumpContext`] inside [`OperationContext`], based on the current node header.
pub fn register_jump_context(node_head: *mut NodeHeader, ctx: &mut ContainerTraversalContext, ocx: &mut OperationContext) {
    // log_to_file("register_jump_context");
    let jump_context: &mut JumpContext = ocx.get_jump_context_mut();
    if as_top_node(node_head).jump_successor_present() {
        jump_context.predecessor = Some(node_head);
        jump_context.sub_nodes_seen = 0;
        jump_context.top_node_predecessor_offset_absolute = ctx.current_container_offset as i32;
    } else {
        jump_context.predecessor = None;
    }
}

pub fn call_top_node(node_head: *mut NodeHeader, rqc: &mut RangeQueryContext, hyperion_callback: HyperionCallback) -> bool {
    match as_top_node(node_head).type_flag() {
        LeafNodeEmpty => hyperion_callback(rqc.current_key, rqc.current_key_offset as u16 + 1, null_mut()),
        LeafNodeWithValue => unsafe {
            hyperion_callback(rqc.current_key, rqc.current_key_offset as u16 + 1, (node_head as *mut u8).add(get_offset_node_value(node_head)))
        },
        Invalid | InnerNode => true,
    }
}

pub fn call_sub_node(node_head: *mut NodeHeader, range_query_context: &mut RangeQueryContext, hyperion_callback: HyperionCallback) -> bool {
    match as_sub_node(node_head).type_flag() {
        LeafNodeEmpty => hyperion_callback(range_query_context.current_key, range_query_context.current_key_offset as u16 + 2, null_mut()),
        LeafNodeWithValue => unsafe {
            hyperion_callback(
                range_query_context.current_key,
                range_query_context.current_key_offset as u16 + 2,
                (node_head as *mut u8).add(get_offset_node_value(node_head)),
            )
        },
        Invalid | InnerNode => true,
    }
}

/// Compares the key of the given node with the key stored in [`OperationContext`].
///
/// # Returns
/// - `true` if the remaining key lengths match of if the keys match.
/// - `false` otherwise.
pub fn compare_path_compressed_node(node_head: *mut NodeHeader, ocx: &mut OperationContext) -> bool {
    // log_to_file("compare_path_compressed_node");
    let pc_header: &PathCompressedNodeHeader = unsafe { as_raw_compressed(node_head).as_ref().expect(ERR_NO_CAST_REF) };

    let overhead = size_of::<PathCompressedNodeHeader>() + pc_header.value_present() as usize * size_of::<NodeValue>();
    let key_len = pc_header.size() - overhead;

    if ocx.key_len_left - 2 != (key_len as i32) {
        // log_to_file("path_compressed_node not equal");
        return false;
    }

    unsafe {
        let op_key = std::slice::from_raw_parts(ocx.key.add(2), key_len);
        let key = std::slice::from_raw_parts((pc_header as *const PathCompressedNodeHeader).add(overhead) as *const u8, key_len);
        if op_key == key {
            // log_to_file("path_compressed_node equal");
        } else {
            // log_to_file("path_compressed_node not equal");
        }
        op_key == key
    }
}

/// Scans the node header's jump table for the second char stored in [`ContainerTraversalContext`].
///
/// # Returns
/// - the destination key if an entry was found.
/// - 0 if no entry was found.
/// # Safety
/// This function is intended for use on [`TopNode`]. Calling this function on a [`SubNode`] will result in undefined behavior.
/// - `node_head` must be a valid, aligned pointer for reading and writing.
pub fn get_destination_from_top_node_jump_table(node_head: *mut NodeHeader, ctx: &mut ContainerTraversalContext) -> u8 {
    // log_to_file("use_sub_node_jump_table");
    // The jump table entry for some key k_i can be found by calculating (k_i >> TOP_NODE_JUMP_TABLE_SHIFT) - 1
    let jump_class = ctx.second_char >> TOP_NODE_JUMP_TABLE_SHIFT;
    // log_to_file(&format!("use_sub_node_jump_table, jumpclass: {}", jump_class));

    ctx.current_container_offset += get_offset(node_head)
        + if jump_class > 0 {
        unsafe {
            read_unaligned(((node_head as *mut u8).add(get_offset_jump_table(node_head)) as *mut u16).add((jump_class - 1) as usize)) as usize
        }
    } else {
        0
    };
    // log_to_file(&format!("use_sub_node_jump_table, set current container offset to: {}", ctx.current_container_offset));

    jump_class << TOP_NODE_JUMP_TABLE_SHIFT
}

/// Creates a new [`PathCompressedEjectionContext`] in [`OperationContext`].
///
/// This function stores the node's key and value in the path compressed context. Additionally, the complete node's header will be stored
/// in the path compressed context.
///
/// # Safety
/// - `node_head` must be a valid, aligned pointer for reading and writing.
pub fn create_path_compressed_context(node_head: *mut NodeHeader, ocx: &mut OperationContext) {
    let pc_node_header: *mut PathCompressedNodeHeader = as_raw_compressed_mut(node_head);
    let pc_ctx: &mut PathCompressedEjectionContext = ocx.path_compressed_ejection_context.get_or_insert(PathCompressedEjectionContext::default());
    let pc_size: usize = unsafe { (*pc_node_header).size() };
    let offset: usize = size_of::<PathCompressedNodeHeader>();
    let value_size: usize = size_of::<NodeValue>();
    // log_to_file(&format!("safe_path_compressed_context: {}, {}", pc_size, offset));

    unsafe {
        let source: *const u8 = (pc_node_header as *const u8).add(offset + if (*pc_node_header).value_present() { value_size } else { 0 });
        let destination: *mut u8 = pc_ctx.partial_key.as_mut_ptr();
        let len: usize = pc_size - (offset + if (*pc_node_header).value_present() { value_size } else { 0 });
        // Copy the contents of the path compressed node into the partial key field in the path compressed context
        copy_nonoverlapping(source, destination, len);

        if (*pc_node_header).value_present() {
            // Copy the path compressed node's value into the path compressed context
            copy_nonoverlapping((pc_node_header as *const u8).add(offset), &mut pc_ctx.node_value as *mut NodeValue as *mut u8, value_size);
        }

        // Store this path compressed node's header in the path compressed context
        copy_nonoverlapping(
            pc_node_header as *const u8,
            &mut pc_ctx.path_compressed_node_header as *mut PathCompressedNodeHeader as *mut u8,
            size_of::<PathCompressedNodeHeader>(),
        );
    }
    pc_ctx.pec_valid = true;
}

/// Deletes the specified node from the root container.
///
/// The deletion will not remove the entire node, but only its contents. Since the node might be used by other jump tables, the node will still
/// remain as empty node in the container.
/// # Safety
/// - `node_head` must be a valid, aligned pointer for reading and writing.
pub fn delete_node(node_head: *mut NodeHeader, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) -> ReturnCode {
    let size_deleted: i16 = if as_top_node(node_head).type_flag() == LeafNodeWithValue {
        size_of::<NodeValue>() as i16
    } else {
        0
    };

    unsafe {
        let container: *mut Container = ocx.get_root_container_pointer();
        let dest: *mut u8 = (node_head as *mut u8).add(get_offset_node_value(node_head));
        let src: *mut u8 = dest.add(size_of::<NodeValue>());
        let remaining_length = (*container).size() as usize - ((*container).free_bytes() as usize + src.offset_from(container as *mut u8) as usize);

        // Remove the specified node by shift-overwriting its contents. Shift the memory behind the node back by the size of the node.
        copy(src, dest, remaining_length);
    }
    as_top_node_mut(node_head).set_type_flag(InnerNode);
    update_space(0 - size_deleted, ocx, ctx);
    OK
}

/// Updates the [`PathCompressedEjectionContext`] in [`OperationContext`] based on the contents of the given node.
/// # Safety
/// - `node_head` must be a valid, aligned pointer for reading and writing.
pub fn update_path_compressed_node(node_head: *mut NodeHeader, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) -> *mut NodeHeader {
    // log_to_file("update_path_compressed_node");
    let input_value: *mut NodeValue = ocx.input_value.unwrap().as_ptr();
    let mut pc_node: *mut PathCompressedNodeHeader = as_raw_compressed_mut(node_head);
    let mut value: *mut u8 = unsafe { (pc_node as *mut u8).add(size_of::<PathCompressedNodeHeader>()) };
    let mut node_head = node_head;

    if !unsafe { *pc_node }.value_present() {
        node_head = new_expand(ocx, ctx, size_of::<NodeValue>() as u32);
        unsafe {
            wrap_shift_container(ocx.get_root_container_pointer(), value, size_of::<NodeValue>());
        }
        update_space(size_of::<NodeValue>() as i16, ocx, ctx);
        pc_node = as_raw_compressed_mut(node_head);
        value = unsafe { (pc_node as *mut u8).add(size_of::<PathCompressedNodeHeader>()) };
    }

    unsafe {
        // log_to_file(&format!("copy input value of {}", unsafe { (*(ocx.input_value.unwrap().as_ptr())).value }));
        // Copy the path compressed node's value into the input value field of OperationContext
        copy_nonoverlapping(input_value as *mut u8, value, size_of::<NodeValue>());
        (*pc_node).set_value_present(true);
    }

    node_head
}

/// Returns all base information needed for ejecting the embedded container.
///
/// # Returns
/// - The offset of the embedded container from the root container.
/// - The size of the embedded container.
/// - The size of the root container.
/// - The amount of free bytes in the root container.
/// - The starting address of the embedded container.
/// - The first address that is behind the embedded container.
fn get_embedded_container_info(ocx: &mut OperationContext, node_head: *mut NodeHeader) -> (usize, u32, u32, u8, *mut u8, *mut u8, usize) {
    let emb_container: &mut AtomicEmbContainer =
        ocx.embedded_traversal_context.embedded_stack.as_mut().expect(ERR_EMPTY_EMB_STACK)[0].as_mut().expect(ERR_EMPTY_EMB_STACK_POS);

    let emb_memory = emb_container.get_as_mut_memory();
    let offset = unsafe { emb_memory.offset_from(ocx.embedded_traversal_context.root_container as *mut u8) as usize };
    let size = unsafe { (*emb_container.get()).size() as u32 };
    let root_container = ocx.get_root_container();

    assert!(root_container.size() > size);

    (
        offset,
        size,
        root_container.size(),
        root_container.free_bytes(),
        unsafe { emb_memory.add(size_of::<EmbeddedContainer>()) },
        unsafe { emb_memory.add(size as usize) },
        get_offset_child_container(node_head),
    )
}

/// Initializes a new container and copies the contents from the source embedded container into the newly created container.
///
/// # Parameters
/// - `source` is the base address of the embedded container (see [`get_embedded_container_info`])
/// - `size` is the size of the embedded container (see [`get_embedded_container_info`])
///
/// # Returns
/// - a new [`HyperionPointer`] pointing to the newly created container
/// # Safety
/// - `node_head` must be a valid, aligned pointer for reading and writing.
fn create_new_container(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, source: *mut u8, size: u32) -> HyperionPointer {
    let mut container_ptr: HyperionPointer = initialize_ejected_container(ocx.get_arena(), size);
    let new_container: *mut Container = get_pointer(ocx.arena, &mut container_ptr, 1, ctx.first_char) as *mut Container;

    unsafe {
        // Skip the containers head, as this will be set separately in the next steps
        let target: *mut u8 = (new_container as *mut u8).add(get_container_head_size());
        // Copy the contents of the old embedded container into the newly created container
        copy_nonoverlapping(source, target, size as usize - size_of::<EmbeddedContainer>());
        (*new_container).set_free_size_left((*new_container).free_bytes() as u32 - (size - size_of::<EmbeddedContainer>() as u32));
    }
    // log_to_file("create new ejected container");
    // log_to_file(&format!("new ejected container pointer: {:?}", container_ptr));
    // log_to_file(&format!("new ejected container: {:?}", unsafe { *new_container }));

    container_ptr
}

/// Adds the new [`HyperionPointer`] created by [`create_new_container`] to the root container.
/// # Safety
/// - `node_head` must be a valid, aligned pointer for reading and writing.
fn link_to_new_container(node_head: *mut NodeHeader, container_ptr: HyperionPointer, child_offset: usize) {
    // Warning: node_head is in the root container, not in the newly created ejected container
    as_sub_node_mut(node_head).set_child_container(Link);
    unsafe {
        // Add the newly created HyperionPointer to the root container
        // This entry in the root container can then be used to jump into the ejected container
        let link_ptr: *mut ContainerLink = (node_head as *mut u8).add(child_offset) as *mut ContainerLink;
        (*link_ptr).ptr = container_ptr;
    }
}

/// Deletes the embedded container from the root container.
///
/// The embedded container will be overwritten by shifting all memory contents behind the old embedded container back.
/// # Safety
/// - `node_head` must be a valid, aligned pointer for reading and writing.
fn shift_memory_after_ejection(
    node_head: *mut NodeHeader, ocx: &mut OperationContext, embedded_offset: usize, embedded_size: u32, shift_src_ptr: *mut u8, root_size: u32,
    free_bytes: u8,
) {
    // If the embedded container used all space of the root container, this will be 0. If the embedded container used only a part of the root container
    // this will be > 0.
    let remaining_size = root_size as usize - (embedded_size as usize + embedded_offset + free_bytes as usize);
    ocx.embedded_traversal_context.embedded_container_depth = 0;

    if remaining_size > 0 {
        unsafe {
            // Shift all memory not belonging to the embedded container back. This overwrites the ejected embedded container.
            copy(shift_src_ptr, (node_head as *mut u8).add(get_offset(node_head)), remaining_size);
        }
    }
}

/// Resets the root container to a valid state.
///
/// This includes updating the root containers size properties, updating all jump tables and zeroing all from the shifting unused memory.
/// # Safety
/// - `node_head` must be a valid, aligned pointer for reading and writing.
fn reset_root_container(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, embedded_size: u32, root_size: u32) -> (i32, i32) {
    // Increase the root container's size by the old embedded container's size
    let delta: i32 = -(embedded_size as i32 - get_container_link_size() as i32);
    // log_to_file(&format!("delta: {}", delta));
    let new_free_size_left: i32 = ocx.get_root_container().free_bytes() as i32 - delta;
    update_space(delta as i16, ocx, ctx);

    assert!(root_size as i32 > new_free_size_left);

    unsafe {
        // free_space_ptr points to all memory that was previously behind the embedded container and is now unused due to the previous back-shifting
        let free_space_ptr: *mut u8 = (ocx.get_root_container_pointer() as *mut u8).add(root_size as usize - new_free_size_left as usize);
        write_bytes(free_space_ptr, 0, new_free_size_left as usize);
    }
    (delta, new_free_size_left)
}

/// Resizes the root container if necessary.
///
/// Due to the ejection of the embedded container, it is very likely that the root container is too large and has a lot of overallocation. In this
/// case, the function will calculate the minimum size needed and reallocate the root container to that size. The root container is guaranteed to
/// shrink in its size during this function.
fn resize_root_container(ocx: &mut OperationContext, delta: i32, root_size: u32, free_bytes: u8, new_free_size_left: i32) {
    let container_increment = GLOBAL_CONFIG.read().header.container_size_increment() as i32;

    if new_free_size_left > CONTAINER_MAX_FREE_BYTES {
        let used_space: i32 = root_size as i32 - (free_bytes as i32 - delta);

        assert!(used_space > 0);

        // Calculate the minimum size needed
        let target_size: u32 = ((used_space + container_increment - 1) / container_increment) as u32 * container_increment as u32;
        let new_free_size: u32 = (free_bytes as i32 - delta) as u32 % container_increment as u32;

        // log_to_file(&format!("target_size: {}", target_size));

        assert_eq!(ocx.embedded_traversal_context.embedded_container_depth, 0);

        unsafe {
            *ocx.embedded_traversal_context.root_container_pointer =
                reallocate(ocx.arena, ocx.embedded_traversal_context.root_container_pointer, target_size as usize, ocx.chained_pointer_hook);
        }

        ocx.embedded_traversal_context.root_container =
            get_pointer(ocx.arena, ocx.embedded_traversal_context.root_container_pointer, 1, ocx.chained_pointer_hook) as *mut Container;

        ocx.get_root_container().set_free_size_left(new_free_size);
        ocx.get_root_container().set_size(target_size);
    }
}

/// Ejects the embedded container stored in [`OperationContext`] from the current root container.
///
/// This includes:
/// 1. Reserving space for a new [`ContainerLink`] inside the root container.
/// 2. Allocating a new container and copying all contents from the embedded container to the newly created container.
/// 3. Linking the newly created container to the root container.
/// 4. Deleting the embedded container from the root container.
/// 5. Resizing and shrinking the root container to fit.
#[allow(unused_assignments)]
pub fn eject_container(mut node_head: *mut NodeHeader, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) {
    // log_to_file("eject_container");
    assert!(ocx.embedded_traversal_context.embedded_container_depth > 0);
    node_head = meta_expand(ocx, ctx, get_container_link_size() as u32);

    let (embedded_offset, embedded_size, root_size, free_bytes, source, shift_src, child_offset) = get_embedded_container_info(ocx, node_head);
    // log_to_file(&format!("offset: {}, size: {}, root_size: {}, free_bytes: {}, child offset: {}", embedded_offset, embedded_size, root_size, free_bytes, child_offset));
    let container_ptr: HyperionPointer = create_new_container(ocx, ctx, source, embedded_size);

    link_to_new_container(node_head, container_ptr, child_offset);
    shift_memory_after_ejection(node_head, ocx, embedded_offset, embedded_size, shift_src, root_size, free_bytes);
    let (delta, new_free_size_left) = reset_root_container(ocx, ctx, embedded_size, root_size);
    resize_root_container(ocx, delta, root_size, free_bytes, new_free_size_left);
}

/// Creates a new [`EmbeddedContainer`] and adds it to the root container.
/// # Safety
/// This function is intended for use on [`SubNode`]. Calling this function on a [`TopNode`] will result in undefined behavior.
/// - `node_head` must be a valid, aligned pointer for reading and writing.
pub fn add_embedded_container(mut node: *mut NodeHeader, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) {
    // log_to_file(&format!("add_embedded_container; for key: {}", get_sub_node_key(node as *mut Node, ctx, false)));
    ocx.header.set_next_container_valid(EmbeddedContainerValid);
    let offset_child_container: usize = get_offset_child_container(node);

    // Reserve space for the embedded container, if the root container is too small to fit the embedded container
    node = new_expand_embedded(ocx, ctx, size_of::<EmbeddedContainer>() as u32);

    ocx.embedded_traversal_context.next_embedded_container =
        unsafe { NonNull::new((node as *mut u8).add(offset_child_container) as *mut EmbeddedContainer) };

    if let Some(next_embedded_container) = ocx.embedded_traversal_context.next_embedded_container {
        unsafe {
            wrap_shift_container(ocx.get_root_container_pointer(), next_embedded_container.as_ptr() as *mut u8, size_of::<EmbeddedContainer>());
        }
    }

    ctx.current_container_offset += offset_child_container;
    // log_to_file(&format!("add_embedded_container set current container offset to: {}", ctx.current_container_offset));
    as_sub_node_mut(node).set_child_container(ChildLinkType::EmbeddedContainer);
    safe_top_node_jump_context(ocx, ctx);

    // Register the embedded container in the operation context
    ocx.embedded_traversal_context.embedded_stack.as_mut().expect(ERR_EMPTY_EMB_STACK)[ocx.embedded_traversal_context.embedded_container_depth] =
        Some(AtomicEmbContainer::new_from_pointer(ocx.embedded_traversal_context.next_embedded_container.unwrap().as_ptr()));
    ocx.embedded_traversal_context.embedded_container_depth += 1;
    // log_to_file(&format!("add_embedded_container increased embedded depth to: {}", ocx.embedded_traversal_context.embedded_container_depth));
    ocx.next_container_pointer = None;
    update_space(size_of::<EmbeddedContainer>() as i16, ocx, ctx);
}

pub enum EmbedLinkCommands {
    CreateLinkToContainer,
    CreatePathCompressedNode,
    CreateEmbeddedContainer,
    TransformPathCompressedNode,
}

/// Returns the next operation to perform on the given node header and the current context.
/// # Safety
/// This function is intended for use on [`SubNode`]. Calling this function on a [`TopNode`] will result in undefined behavior.
fn get_operation(node_head: *mut NodeHeader, ocx: &mut OperationContext, size_pc: i32) -> EmbedLinkCommands {
    let sub_node = as_sub_node(node_head);
    let container_limit = GLOBAL_CONFIG.read().container_embedding_limit as i32;
    let root_size = ocx.get_root_container().size() as i32;
    let embedded_depth = ocx.embedded_traversal_context.embedded_container_depth;

    if sub_node.child_container() == PathCompressed {
        // log_to_file("CC1: TransformPath");
        return TransformPathCompressedNode;
    } else if root_size + size_pc < container_limit {
        // The current root container size + the size required for path compression do not exceed the root container's size limit

        if embedded_depth == 0 {
            return if size_pc < MAX_KEY_LENGTH_PATH_COMPRESSION {
                // The node can be stored as path compressed node
                // log_to_file("CC2: CreatePath");
                CreatePathCompressedNode
            } else {
                // Path compressed size is too large
                // At this point it is more efficient to create a new embedded container
                // log_to_file("CC3: CreateEmbed");
                CreateEmbeddedContainer
            };
        } else if embedded_depth < CONTAINER_MAX_EMBEDDED_DEPTH {
            // There is already some embedded container stored in the root container
            let embedded_stack = ocx.embedded_traversal_context.embedded_stack.as_mut().expect(ERR_EMPTY_EMB_STACK);
            let embedded_size = embedded_stack[0].as_mut().expect(ERR_EMPTY_EMB_STACK_POS).borrow_mut().size() as i32;

            if embedded_size + size_pc < (GLOBAL_CONFIG.read().header.container_embedding_high_watermark() as i32)
                && size_pc < MAX_KEY_LENGTH_PATH_COMPRESSION
            {
                // The node can be stored as path compressed node
                // log_to_file("CC4: CreatePath");
                return CreatePathCompressedNode;
            } else if embedded_size < (GLOBAL_CONFIG.read().header.container_embedding_high_watermark() as i32) {
                // Path compressed size is too large
                // At this point it is more efficient to create a new embedded container
                // log_to_file("CC5: CreateEmbed");
                return CreateEmbeddedContainer;
            }
        }
        return CreateLinkToContainer;
    } else if sub_node.child_container() == ChildLinkType::None
        && size_pc < 16
        && root_size < (2 * GLOBAL_CONFIG.read().header.container_embedding_high_watermark() as i32)
    {
        // log_to_file("CC6: CreatePath");
        return CreatePathCompressedNode;
    }

    CreateLinkToContainer
}

/// Creates or updates a child container for the given [`SubNode`].
/// # Safety
/// This function is intended for use on [`SubNode`]. Calling this function on a [`TopNode`] will result in undefined behavior.
/// - `node_head` must be a valid, aligned pointer for reading and writing.
pub fn create_child_container(mut node_head: *mut NodeHeader, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) -> *mut NodeHeader {
    let required_size_for_path_compression =
        size_of::<PathCompressedNodeHeader>() as i32 + ocx.key_len_left - 2 + ocx.input_value.map_or(0, |_| size_of::<NodeValue>()) as i32;

    match get_operation(node_head, ocx, required_size_for_path_compression) {
        TransformPathCompressedNode => {
            // log_to_file("TransformPathCompressedNode");
            transform_pc_node(node_head, ocx, ctx);
            node_head = unsafe { (ocx.embedded_traversal_context.root_container as *mut NodeHeader).add(ctx.current_container_offset) };
        },
        CreateEmbeddedContainer => {
            // log_to_file("CreateEmbeddedContainer");
            assert_eq!(as_sub_node(node_head).child_container(), ChildLinkType::None);
            add_embedded_container(node_head, ocx, ctx);
            node_head = unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ctx.current_container_offset) as *mut NodeHeader };
        },
        CreatePathCompressedNode => {
            let offset: usize = get_offset_child_container(node_head);
            // log_to_file(&format!("CreatePathCompressedNode; offset: {}", offset));

            if (ocx.get_root_container().free_bytes() as i32) < required_size_for_path_compression {
                // Root container is too small to fit the path compressed node
                // Reserve additional space for the path compressed node
                node_head = meta_expand(ocx, ctx, required_size_for_path_compression as u32);
            }

            unsafe {
                let target: *mut PathCompressedNodeHeader = (node_head as *mut u8).add(offset) as *mut PathCompressedNodeHeader;
                // Shift the root container's memory to fit the path compressed node
                wrap_shift_container(ocx.get_root_container_pointer(), target as *mut u8, required_size_for_path_compression as usize);
                (*target).set_size(required_size_for_path_compression as usize);
                // log_to_file(&format!("set path compressed size to: {}", unsafe { (*target).size() }));

                let mut target_partial_key: *mut u8 = (target as *mut u8).add(size_of::<PathCompressedNodeHeader>());

                if let Some(input_value) = ocx.input_value {
                    (*target).set_value_present(true);
                    // Copy the input value into the path compressed node
                    // log_to_file(&format!("copy input value of {}", (*(input_value.as_ptr())).value));
                    copy_nonoverlapping(input_value.as_ptr() as *mut u8, target_partial_key, size_of::<NodeValue>());
                    target_partial_key = target_partial_key.add(size_of::<NodeValue>());
                } else {
                    panic!("{}", ERR_NO_INPUT_VALUE)
                }

                // Copy the stored key behind the previously stored value
                copy_nonoverlapping(ocx.key.add(2), target_partial_key, (ocx.key_len_left - 2) as usize);
                as_sub_node_mut(node_head).set_child_container(PathCompressed);
            }

            update_space(required_size_for_path_compression as i16, ocx, ctx);
            ocx.header.set_next_container_valid(ContainerValidTypes::Invalid);
            ocx.header.set_operation_done(true);
            ocx.header.set_performed_put(true);
        },
        CreateLinkToContainer => {
            // log_to_file("CreateLinkToContainer");
            if (ocx.get_root_container().free_bytes() as usize) < get_container_link_size() {
                // The root container is too small to fit a HyperionPointer in its memory
                // Reallocate root container
                node_head = meta_expand(ocx, ctx, get_container_link_size() as u32);
            }

            unsafe {
                let target: *mut u8 = (node_head as *mut u8).add(get_offset_child_container(node_head));
                // Shift the root container's memory to fit a HyperionPointer
                wrap_shift_container(ocx.get_root_container_pointer(), target, get_container_link_size());
                let new_link: *mut ContainerLink = target as *mut ContainerLink;

                // Create a new container and store its HyperionPointer in the root container
                // Store the newly created HyperionPointer as next pointer
                (*new_link).ptr = initialize_container(ocx.arena);
                ocx.next_container_pointer = Some(&mut (*new_link).ptr as *mut HyperionPointer);
                as_sub_node_mut(node_head).set_child_container(Link);
            }
            ocx.header.set_next_container_valid(ContainerValid);
            update_space(get_container_link_size() as i16, ocx, ctx);
            ocx.embedded_traversal_context.embedded_container_depth = 0;
        },
    }
    node_head
}

/// Handles the child container pointer retrival for an embedded container.
///
/// # Parameters
/// If `modify` is false, the current [`OperationContext`] will be updated and a pointer to the next embedded container will be stored in
/// the next_container_pointer field. If `modify` is true, this function will check if the embedded container might exceed the root containers
/// size limits and eject the embedded container, if necessary.
/// # Safety
/// This function is intended for use on [`SubNode`]. Calling this function on a [`TopNode`] will result in undefined behavior.
/// - `node_head` must be a valid, aligned pointer for reading and writing.
fn process_embedded_container(
    node_head: *mut NodeHeader, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, modify: bool,
) -> (ReturnCode, *mut NodeHeader) {
    // log_to_file("process_embedded_container");
    safe_top_node_jump_context(ocx, ctx);
    let offset: usize = get_offset_child_container(node_head);

    // Store a pointer to the embedded container of the sub node
    ocx.embedded_traversal_context.next_embedded_container = NonNull::new(unsafe { (node_head as *mut u8).add(offset) as *mut EmbeddedContainer });
    /*log_to_file(&format!("set next embedded container; key: {}, size: {}", get_sub_node_key(node_head as *mut Node, ctx, false), unsafe {
        (*(ocx.embedded_traversal_context.next_embedded_container.unwrap().as_ptr())).size()
    }));*/
    assert!(unsafe { (*(ocx.embedded_traversal_context.next_embedded_container.unwrap().as_ptr())).size() as u32 } < ocx.get_root_container().size());

    if ocx.embedded_traversal_context.embedded_stack.is_none() {
        ocx.embedded_traversal_context.embedded_stack = Some([const { None }; CONTAINER_MAX_EMBEDDED_DEPTH]);
    }

    ocx.embedded_traversal_context.embedded_stack.as_mut().expect(ERR_EMPTY_EMB_STACK)[ocx.embedded_traversal_context.embedded_container_depth] =
        Some(AtomicEmbContainer::new_from_pointer(ocx.embedded_traversal_context.next_embedded_container.unwrap().as_ptr()));
    ocx.embedded_traversal_context.embedded_container_depth += 1;

    let embedded_size = unsafe { (*(ocx.embedded_traversal_context.next_embedded_container.unwrap().as_ptr())).size() as u32 };
    let root_size = ocx.get_root_container().size();
    let embedding_hwm = GLOBAL_CONFIG.read().header.container_embedding_high_watermark();
    let embedding_limit = GLOBAL_CONFIG.read().container_embedding_limit;

    if modify
        && ocx.header.command() == Put
        && (embedded_size > embedding_hwm || root_size >= embedding_limit || (embedded_size > embedding_hwm / 2 && root_size >= embedding_limit / 2))
    {
        // 1.) The embedded container and root container exceed their size limits
        // 2.) After an ejection, both root container and ejected embedded container are large enough to be efficient
        eject_container(node_head, ocx, ctx);

        // Return ChildContainerMissing, so the get_child_container_pointer can retrieve the HyperionPointer from the root container
        (ChildContainerMissing, unsafe {
            (ocx.embedded_traversal_context.root_container as *mut u8).add(ctx.current_container_offset) as *mut NodeHeader
        })
    } else {
        // The embedded and root containers are within their size limits
        ctx.current_container_offset += offset;
        // log_to_file(&format!("process_embedded_container set current container offset to: {}", ctx.current_container_offset));
        ocx.header.set_next_container_valid(EmbeddedContainerValid);
        ocx.next_container_pointer =
            Some(ocx.embedded_traversal_context.next_embedded_container.expect(ERR_NO_POINTER).as_ptr() as *mut HyperionPointer);
        (OK, node_head)
    }
}

/// Returns the child container pointer for the child container of the given [`SubNode`].
/// # Safety
/// This function is intended for use on [`SubNode`]. Calling this function on a [`TopNode`] will result in undefined behavior.
/// - `node_head` must be a valid, aligned pointer for reading and writing.
pub fn get_child_container_pointer(
    mut node_head: *mut NodeHeader, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, modify: bool,
) -> ReturnCode {
    let node_link_type = as_sub_node(node_head).child_container();

    if !matches!(node_link_type, ChildLinkType::EmbeddedContainer | Link) {
        return ChildContainerMissing;
    }

    if matches!(node_link_type, ChildLinkType::EmbeddedContainer) {
        let (ret, node_header) = process_embedded_container(node_head, ocx, ctx, modify);
        node_head = node_header;

        if ret == OK {
            // Both embedded and root containers are within their size limits
            // The child container pointer was stored in the next_container_pointer field of the OperationContext
            return OK;
        }
    }

    // The embedded container was ejected
    // The child container pointer must be retrieved from the root container
    if let Some(ref mut next_ptr) = ocx.next_container_pointer {
        // log_to_file("update next container pointer");
        // let value = unsafe { *((node_head as *mut u8).add(get_offset_child_container(node_head))) };
        // log_to_file(&format!("root container offset value: {}", value));
        *next_ptr = unsafe { (node_head as *mut u8).add(get_offset_child_container(node_head)) as *mut HyperionPointer };
    }

    ocx.embedded_traversal_context.embedded_container_depth = 0;
    ocx.header.set_next_container_valid(ContainerValid);
    ocx.embedded_traversal_context.next_embedded_container = None;
    OK
}

/// Contains all options that can be set for a creation of a new node.
pub struct NodeCreationOptions {
    /// Stores the [`NodeState`] for the new node.
    pub container_depth: NodeState,
    /// Stores if the key should be automatically set from the current [`ContainerTraversalContext`]
    pub set_key: bool,
    /// Stores if the nodes value should be set from the input_value field of [`OperationContext`].
    pub add_value: bool,
    /// Stores the key's delta from the predecessor node.
    pub key_delta: u8,
    /// Stores if the creation happens in a [`Container`] or an [`EmbeddedContainer`].
    pub embedded: bool,
}

/// Creates a new node at the memory region pointed to by `node_head`.
///
/// The options for a node creations can be specified by using [`NodeCreationOptions`].
/// # Safety
/// - `node_head` must be a valid, aligned pointer for reading and writing.
#[allow(unused_assignments)]
pub fn create_node(
    mut node_head: *mut NodeHeader, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, options: NodeCreationOptions,
) -> *mut NodeHeader {
    let mut absolute_key: u8 = if options.embedded && options.container_depth == NodeState::TopNode {
        ctx.first_char
    } else {
        ctx.second_char
    };

    let input_memory_consumption: usize = ocx.input_value.map_or(0, |_| options.add_value as usize * size_of::<NodeValue>());
    let required: usize = size_of::<NodeHeader>() + options.set_key as usize + input_memory_consumption;
    /*log_to_file(&format!(
        "create_node: embedded: {}, absolute_key: {}, input_mem: {}, required: {}, set key: {}, add value: {}, container depth: {}, key delta: {}",
        options.embedded as u8, absolute_key, input_memory_consumption, required, options.set_key as u8, options.add_value as u8, options.container_depth as u8, options.key_delta
    ));*/

    if !options.embedded && options.container_depth == NodeState::TopNode {
        // Reset the jump context for the insertion of a new top node
        ocx.jump_context.predecessor = None;
        ocx.jump_context.top_node_key = ctx.first_char as i32;
        absolute_key = ctx.first_char;
    }

    // Allocate new space if container is too small to fit a new node
    node_head = if options.embedded {
        new_expand_embedded(ocx, ctx, required as u32)
    } else {
        new_expand(ocx, ctx, required as u32)
    };

    if options.embedded {
        // If the new node is not inserted at the end, but somewhere in already existing data, remaining_space will be > 0
        // Shift all data to the right to fit a new node
        let remaining_space: i32 = unsafe {
            ocx.get_root_container().size() as i32
                - (ocx.get_root_container().free_bytes() as i32
                + ((node_head as *mut u8).offset_from(ocx.embedded_traversal_context.root_container as *mut u8) as i32))
        };

        if remaining_space > 0 {
            // log_to_file("remaining space > 0, shift container");
            unsafe {
                shift_container(node_head as *mut u8, required, remaining_space as usize);
            }
        }
    }

    if !options.embedded {
        // log_to_file(&format!("check force shift, currently {}", ctx.header.force_shift_before_insert() as usize));
        if ctx.header.force_shift_before_insert() {
            // log_to_file("wrap shift container");
            unsafe {
                wrap_shift_container(ocx.get_root_container_pointer(), node_head as *mut u8, required);
            }
        }
        assert!(unsafe { *(node_head as *mut u8) == 0 })
    }

    as_top_node_mut(node_head).set_type_flag(if options.add_value && input_memory_consumption != 0 {
        LeafNodeWithValue
    } else {
        InnerNode
    });
    as_top_node_mut(node_head).set_container_type(options.container_depth);
    update_space(
        if !options.embedded {
            1 + input_memory_consumption + options.set_key as usize
        } else {
            required
        } as i16,
        ocx,
        ctx,
    );

    if options.set_key {
        // Store the absolute key explicitly as a node value
        set_nodes_key(node_head as *mut Node, ocx, ctx, options.embedded, absolute_key);
    } else {
        // Store the nodes key implicitly by using delta encoding
        as_top_node_mut(node_head).set_delta(options.key_delta);
        let mut successor_ptr: Option<*mut Node> = None;
        let skipped_bytes: u32 = get_successor(node_head, &mut successor_ptr, ocx, ctx, options.embedded);

        if let Some(successor) = successor_ptr.filter(|_| skipped_bytes > 0) {
            // If there is some successor key, update its key based on the difference and this nodes absolute key
            let successor: &mut Node = unsafe { successor.as_mut().expect(ERR_NO_CAST_MUT_REF) };
            let diff: u8 = if as_top_node(&mut successor.header).delta() == 0 {
                successor.key - options.key_delta
            } else {
                as_top_node(&mut successor.header).delta() - options.key_delta
            };
            update_successor_key(successor as *mut Node, diff, absolute_key + diff, skipped_bytes, ocx, ctx);
        }
    }

    if options.add_value {
        set_node_value(node_head, ocx);
    }

    if !ctx.header.end_operation() && options.container_depth == NodeState::SubNode {
        if options.embedded {
            as_sub_node_mut(node_head).set_child_container(ChildLinkType::None);
        }
        node_head = create_child_container(node_head, ocx, ctx);
    }
    ocx.header.set_performed_put(true);
    node_head
}

/// Returns if the successor node is invalid.
///
/// An invalid successor node occurs either by iterating over the memory bounds of the container or by finding an invalid, empty node.
/// # Safety
/// - `successor` must be a valid, aligned pointer for reading and writing.
fn is_invalid_successor(
    successor: *mut Node, skipped_bytes: u32, embedded: bool, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext,
) -> bool {
    let container_limit = if embedded {
        unsafe { (*(ocx.embedded_traversal_context.next_embedded_container.expect(ERR_NO_NEXT_CONTAINER).as_ptr())).size() as u32 }
    } else {
        ocx.get_root_container().size()
    };

    if ctx.current_container_offset as u32 + skipped_bytes >= container_limit {
        return true;
    }

    if unsafe { as_top_node(&mut (*successor).header).type_flag() == Invalid } {
        return true;
    }

    false
}

/// Searches and returns the successor node of `node_head`, if exists.
///
/// # Returns
/// - The amount of skipped bytes.
/// - The successor node in `successor`, if exists.
/// # Safety
/// - `node_head` must be a valid, aligned pointer for reading and writing.
pub fn get_successor(
    node_head: *mut NodeHeader, successor: &mut Option<*mut Node>, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, embedded: bool,
) -> u32 {
    let mut successor_ptr: *mut Node;
    let mut skipped_bytes: u32 = 0;

    if as_top_node(node_head).container_type() == NodeState::TopNode {
        if !embedded && as_top_node(node_head).jump_successor_present() {
            skipped_bytes = get_jump_successor_value(node_head) as u32;
            successor_ptr = unsafe { (node_head as *mut u8).add(skipped_bytes as usize) as *mut Node };
        } else {
            successor_ptr = node_head as *mut Node;

            loop {
                let offset: usize = unsafe { get_offset(&mut (*successor_ptr).header) };
                skipped_bytes += offset as u32;
                successor_ptr = unsafe { (successor_ptr as *mut u8).add(offset) as *mut Node };

                if is_invalid_successor(successor_ptr, skipped_bytes, embedded, ocx, ctx) {
                    return 0;
                }

                if unsafe { as_top_node(&mut (*successor_ptr).header).container_type() == NodeState::TopNode } {
                    break;
                }
            }
        }
    } else {
        skipped_bytes = get_offset_sub_node(node_head) as u32;
        successor_ptr = unsafe { (node_head as *mut u8).add(skipped_bytes as usize) as *mut Node };

        if is_invalid_successor(successor_ptr, skipped_bytes, embedded, ocx, ctx) {
            return 0;
        }

        if unsafe { as_top_node(&mut (*successor_ptr).header).container_type() == NodeState::TopNode } {
            return 0;
        }
    }

    // log_to_file(&format!("get_successor: embedded: {}, skipped: {}", embedded as u8, skipped_bytes));

    if skipped_bytes > 0 {
        *successor = Some(successor_ptr);
    }
    skipped_bytes
}

/// Creates a completely new [`TopNodeJumpTable`] for the given top node.
///
/// This function automatically reserves space for the top node's jump table, scans through all sub nodes and adds jump table entries for them.
/// If keys are missing, this function will insert dummy sub nodes in order to generate a complete jump table.
/// # Safety
/// This function is intended for use on [`TopNode`]. Calling this function on a [`SubNode`] will result in undefined behavior.
/// - `node_head` must be a valid, aligned pointer for reading and writing.
pub fn create_top_node_jump_table(mut node_head: *mut NodeHeader, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) {
    // log_to_file("create_sublevel_jumptable");

    // A top node jump table entry references the sub node storing the 8-bit partial key 16 * (i + 1)
    const JUMP_TABLE_KEYS: [u8; 15] = [16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240];

    assert!(!as_top_node(node_head).jump_table_present());

    let maximum_size_jump_table = size_of::<TopNodeJumpTable>() + TOP_NODE_JUMP_TABLE_ENTRIES * (size_of::<NodeHeader>() + 1);
    let mut container_free_bytes = ocx.get_root_container().free_bytes() as usize;

    let node_offset = unsafe { (node_head as *mut u8).offset_from(ocx.get_root_container_pointer() as *mut u8) as usize };
    let offset_to_jump_table = node_offset + get_offset_jump_table(node_head);
    let mut bytes_to_move = ocx.get_root_container().size() as i32 - (offset_to_jump_table as i32 + container_free_bytes as i32);

    /*log_to_file(&format!(
        "free: {}, offset: {}, offset to jt0: {}, move: {}",
        ocx.get_root_container().free_bytes(),
        node_offset,
        offset_to_jump_table,
        bytes_to_move
    ));*/

    // Reserve additional space, if the root container is too small to fit a max-sized top node jump table
    if container_free_bytes <= maximum_size_jump_table {
        new_expand(ocx, ctx, maximum_size_jump_table as u32);
    }

    // Shift contents of jump table to fit a top node jump table
    let mut jump_table: *mut u16 = unsafe { (ocx.get_root_container_pointer() as *mut u8).add(offset_to_jump_table) as *mut u16 };
    unsafe { shift_container(jump_table as *mut u8, size_of::<TopNodeJumpTable>(), bytes_to_move as usize) };
    update_space(size_of::<TopNodeJumpTable>() as i16, ocx, ctx);
    node_head = unsafe { (ocx.get_root_container_pointer() as *mut u8).add(node_offset) as *mut NodeHeader };
    unsafe { _mm_prefetch::<_MM_HINT_T0>(node_head as *const i8); }
    unsafe { _mm_prefetch::<_MM_HINT_T0>(as_top_node(node_head) as *const _ as *const i8); }

    // Create a temporary container traversal context, so the original traversal context doesn't get polluted
    let mut tmp_ctx = ContainerTraversalContext {
        current_container_offset: node_offset,
        ..ContainerTraversalContext::default()
    };
    tmp_ctx.header.set_in_first_char_scope(true);
    tmp_ctx.header.set_last_sub_char_set(false);

    let base_offset = tmp_ctx.current_container_offset + get_offset(node_head) + size_of::<TopNodeJumpTable>();
    let mut node_offset = 0;
    let mut jump_table_index = 0;

    loop {
        tmp_ctx.current_container_offset = base_offset + node_offset;
        // log_to_file(&format!("create_sublevel_jumptable set current container offset to {}", tmp_ctx.current_container_offset));

        let scan_node = unsafe { (ocx.get_root_container_pointer() as *mut u8).add(tmp_ctx.current_container_offset) as *mut NodeHeader };

        if as_top_node(scan_node).container_type() == NodeState::SubNode {
            let mut key: u8 = get_sub_node_key(scan_node as *mut Node, &mut tmp_ctx, false);
            // log_to_file(&format!("found key {}", key));

            // A top node jump table entry references the sub node storing the 8-bit partial key 16 * (i + 1).
            // In this branch a sub node is found. In order to store a jump to this sub node, the sub node's key must be at least
            // >= 16 * (i + 1), which is encoded in JUMP_TABLE_KEYS[i].
            match key.cmp(&JUMP_TABLE_KEYS[jump_table_index]) {
                Ordering::Less => {},
                ord @ (Ordering::Equal | Ordering::Greater) => {
                    if ord == Ordering::Greater {
                        insert_top_jump_table_reference_key(scan_node, ocx, &mut tmp_ctx, JUMP_TABLE_KEYS[jump_table_index]);
                        key = JUMP_TABLE_KEYS[jump_table_index];
                    }

                    // Write the current iterator value of jump_table to the current jump table entry referenced by node_offset
                    unsafe {
                        write_unaligned(jump_table, node_offset as u16);
                    }
                    // log_to_file(&format!("key equal, written target to {}", unsafe { read_unaligned(jump_table) }));

                    // Update the current index and shift the jump_table pointer to the next jump table entry
                    jump_table_index += 1;
                    jump_table = unsafe { jump_table.add(1) };

                    if jump_table_index == TOP_NODE_JUMP_TABLE_ENTRIES {
                        // if the jump table if full, end this function
                        break;
                    }
                },
            }

            // Store the last key seen and move the scan node to the next node
            tmp_ctx.last_sub_char_seen = key;
            tmp_ctx.header.set_last_sub_char_set(true);
            node_offset += get_offset(scan_node);
        } else {
            // A top node was found, which indicates a missing key. In order to fill the jump table, the current scan node is inserted as a
            // "dummy" node.
            assert!(tmp_ctx.header.last_sub_char_set());
            assert!(jump_table_index < TOP_NODE_JUMP_TABLE_ENTRIES);
            assert!(JUMP_TABLE_KEYS[jump_table_index] > tmp_ctx.last_sub_char_seen);

            // update the number of bytes to move
            container_free_bytes = ocx.get_root_container().free_bytes() as usize;
            bytes_to_move = ocx.get_root_container().size() as i32
                - (unsafe { (scan_node as *mut u8).offset_from(ocx.get_root_container_pointer() as *mut u8) as i32 } + container_free_bytes as i32);

            // log_to_file(&format!("insert jumptable: free: {}, move: {}", container_free_bytes, bytes_to_move));

            // get the number of missing jump table entries
            // get the difference between the expected minimal value for the current index and the last key seen
            let num_missing = TOP_NODE_JUMP_TABLE_ENTRIES - jump_table_index;
            let diff = JUMP_TABLE_KEYS[jump_table_index] - tmp_ctx.last_sub_char_seen;

            // check if the difference can be stored as delta encoding
            let can_be_delta_encoded = diff <= DELTA_MAX_VALUE;
            let shift_by: usize = ((size_of::<NodeHeader>() + 1) * num_missing) - can_be_delta_encoded as usize;

            // log_to_file(&format!("num missing: {}, diff: {}, relative: {}, shift_by: {}", num_missing, diff, can_be_delta_encoded as u8, shift_by));

            // Shift the containers memory to fit the scan node as new sub node
            unsafe {
                shift_container(scan_node as *mut u8, shift_by, bytes_to_move.max(0) as usize);
            }
            update_space(shift_by as i16, ocx, &mut tmp_ctx);

            // Add the scan node as new sub node
            as_sub_node_mut(scan_node).set_type_flag(InnerNode);
            as_sub_node_mut(scan_node).set_container_type(NodeState::SubNode);

            if !can_be_delta_encoded {
                unsafe {
                    *((scan_node as *mut u8).add(1)) = diff;
                }
                tmp_ctx.last_sub_char_seen = JUMP_TABLE_KEYS[jump_table_index];
            } else {
                as_sub_node_mut(scan_node).set_delta(diff);
            }

            unsafe {
                // Write the jump to the newly created "dummy" node in the top node's jump table
                write_unaligned(jump_table, node_offset as u16);
                jump_table = jump_table.add(1);
            }
            node_offset += get_offset(scan_node);
            jump_table_index += 1;

            while jump_table_index < TOP_NODE_JUMP_TABLE_ENTRIES {
                // Create "dummy" sub nodes in order to fill up the remaining empty jump table entries.
                let scan_node = unsafe { (ocx.get_root_container_pointer() as *mut u8).add(base_offset + node_offset) as *mut NodeHeader };
                as_sub_node_mut(scan_node).set_type_flag(InnerNode);
                as_sub_node_mut(scan_node).set_container_type(NodeState::SubNode);
                as_sub_node_mut(scan_node).set_delta(0);

                unsafe {
                    // Store the difference between the expected minimum key and the last key seen as the dummy node's key
                    *(scan_node as *mut u8).add(size_of::<NodeHeader>()) = JUMP_TABLE_KEYS[jump_table_index] - tmp_ctx.last_sub_char_seen;
                }
                tmp_ctx.last_sub_char_seen = JUMP_TABLE_KEYS[jump_table_index];
                jump_table_index += 1;
                unsafe {
                    // Write a jump table entry to the newly created dummy node
                    write_unaligned(jump_table, node_offset as u16);
                    jump_table = jump_table.add(1);
                }
                node_offset += get_offset(scan_node);
            }
            break;
        }
    }
    as_top_node_mut(node_head).set_jump_table_present(true);
}

pub fn handle_link_transformation(
    mut node_head: *mut NodeHeader, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, child_container_offset: usize, pc_key_len: usize,
) {
    let pc_delta: i32 = ocx.get_pc_ejection_context().path_compressed_node_header.size() as i32 - get_container_link_size() as i32;
    if pc_delta < 0 {
        node_head = meta_expand(ocx, ctx, get_container_link_size() as u32);
    }

    as_sub_node_mut(node_head).set_child_container(Link);
    let free_size_left: u8 = ocx.get_root_container().free_bytes();
    let link: *mut ContainerLink = unsafe { (node_head as *mut u8).add(child_container_offset) as *mut ContainerLink };
    let diff: i32 = get_container_link_size() as i32 - ocx.get_pc_ejection_context().path_compressed_node_header.size() as i32;
    let absolute_offset: isize = unsafe { (node_head as *mut u8).offset_from(ocx.get_root_container_pointer() as *mut u8) };
    let container_tail: i32 = ocx.get_root_container().size() as i32
        - (absolute_offset as i32
        + child_container_offset as i32
        + ocx.get_pc_ejection_context().path_compressed_node_header.size() as i32
        + free_size_left as i32);

    // log_to_file(&format!("free: {}, diff: {}, absolute: {}, tail: {}", free_size_left, diff, absolute_offset, container_tail));
    unsafe {
        let tail_target: *mut u8 = (link as *mut u8).add(get_container_link_size());
        copy(tail_target.add(pc_delta as usize), tail_target, container_tail as usize);
        if pc_delta >= 0 {
            write_bytes(tail_target.add(container_tail as usize), 0, pc_delta as usize);
        }
        update_space(diff as i16, ocx, ctx);
        (*link).ptr = initialize_container(ocx.get_arena());
        ocx.embedded_traversal_context.root_container = get_pointer(ocx.get_arena(), &mut (*link).ptr, 1, ocx.chained_pointer_hook) as *mut Container;
        ocx.next_container_pointer = Some(&mut (*link).ptr as *mut HyperionPointer);
    }

    ocx.embedded_traversal_context.embedded_container_depth = 0;
    ocx.header.set_next_container_valid(ContainerValid);
    ocx.embedded_traversal_context.next_embedded_container = None;
    ocx.embedded_traversal_context.root_container_pointer = ocx.next_container_pointer.expect(ERR_NO_POINTER);
    ctx.current_container_offset = ocx.get_root_container().get_container_head_size();

    let data_offset: *mut u8 = unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ocx.get_root_container().get_container_head_size()) };
    let consumed_newcon: usize;
    assert!(pc_key_len > 0);

    let top: *mut NodeHeader = data_offset as *mut NodeHeader;
    as_top_node_mut(top).set_type_flag(InnerNode);
    // log_to_file(&format!("copy partial key of: {}", ocx.get_pc_ejection_context().partial_key[0]));
    unsafe {
        copy_nonoverlapping(ocx.get_pc_ejection_context().partial_key.as_mut_ptr(), (top as *mut u8).add(size_of::<NodeHeader>()), 1);
    }
    ctx.current_container_offset += 2;

    if pc_key_len == 1 {
        // log_to_file("Trafo1-1");
        // Insert leaf node
        if ocx.get_pc_ejection_context().path_compressed_node_header.value_present() {
            as_top_node_mut(top).set_type_flag(LeafNodeWithValue);
            consumed_newcon = 2 + size_of::<NodeValue>();
            unsafe {
                copy_nonoverlapping(
                    &mut ocx.get_pc_ejection_context().node_value as *mut NodeValue as *mut u8,
                    (top as *mut u8).add(size_of::<NodeHeader>() + 1),
                    size_of::<NodeValue>(),
                );
            }
        } else {
            as_top_node_mut(top).set_type_flag(LeafNodeEmpty);
            consumed_newcon = 2;
        }
    } else if pc_key_len == 2 {
        // log_to_file("Trafo1-2");
        let sub: *mut NodeHeader = unsafe { data_offset.add(size_of::<NodeHeader>() + 1) as *mut NodeHeader };
        as_sub_node_mut(sub).set_container_type(NodeState::SubNode);
        unsafe {
            copy_nonoverlapping(ocx.get_pc_ejection_context().partial_key.as_mut_ptr().add(1), (sub as *mut u8).add(size_of::<NodeHeader>()), 1);
        }

        if ocx.get_pc_ejection_context().path_compressed_node_header.value_present() {
            as_sub_node_mut(sub).set_type_flag(LeafNodeWithValue);
            consumed_newcon = 4 + size_of::<NodeValue>();
            unsafe {
                copy_nonoverlapping(
                    &mut ocx.get_pc_ejection_context().node_value as *mut NodeValue as *mut u8,
                    (sub as *mut u8).add(size_of::<NodeHeader>() + 1),
                    size_of::<NodeValue>(),
                );
            }
        } else {
            as_sub_node_mut(sub).set_type_flag(LeafNodeEmpty);
            consumed_newcon = 4;
        }
    } else {
        // log_to_file("Trafo1-3");
        let mut sub: *mut NodeHeader = unsafe { data_offset.add(size_of::<NodeHeader>() + 1) as *mut NodeHeader };
        as_sub_node_mut(sub).set_container_type(NodeState::SubNode);
        as_sub_node_mut(sub).set_type_flag(InnerNode);
        unsafe {
            copy_nonoverlapping(ocx.get_pc_ejection_context().partial_key.as_mut_ptr().add(1), (sub as *mut u8).add(size_of::<NodeHeader>()), 1);
        }

        as_sub_node_mut(sub).set_child_container(PathCompressed);
        let remaining_pc_key_len: usize = pc_key_len - 2;
        let required: usize =
            ocx.get_pc_ejection_context().path_compressed_node_header.value_present() as usize * size_of::<NodeValue>() + remaining_pc_key_len + 1;
        consumed_newcon = 2 + 2 * size_of::<NodeHeader>() + required;
        sub = meta_expand(ocx, ctx, consumed_newcon as u32);

        let pc_node: *mut PathCompressedNodeHeader = unsafe { (sub as *mut u8).add(size_of::<NodeHeader>() + 1) as *mut PathCompressedNodeHeader };

        unsafe {
            if ocx.get_pc_ejection_context().path_compressed_node_header.value_present() {
                (*pc_node).set_value_present(true);
                (*pc_node).set_size(size_of::<PathCompressedNodeHeader>() + size_of::<NodeValue>() + remaining_pc_key_len);
                copy_nonoverlapping(
                    &mut ocx.get_pc_ejection_context().node_value as *mut NodeValue as *mut u8,
                    (pc_node as *mut u8).add(size_of::<PathCompressedNodeHeader>()),
                    size_of::<NodeValue>(),
                );
                copy_nonoverlapping(
                    ocx.get_pc_ejection_context().partial_key.as_mut_ptr().add(2),
                    (pc_node as *mut u8).add(size_of::<PathCompressedNodeHeader>() + size_of::<NodeValue>()),
                    remaining_pc_key_len,
                );
            } else {
                (*pc_node).set_value_present(false);
                (*pc_node).set_size(size_of::<PathCompressedNodeHeader>() + remaining_pc_key_len);
                copy_nonoverlapping(
                    ocx.get_pc_ejection_context().partial_key.as_mut_ptr().add(2),
                    (pc_node as *mut u8).add(size_of::<PathCompressedNodeHeader>()),
                    remaining_pc_key_len,
                );
            }
        }
    }
    assert!(ocx.get_root_container().free_bytes() as usize >= consumed_newcon);
    let current_value = ocx.get_root_container().free_bytes();
    ocx.get_root_container().set_free_bytes(current_value - consumed_newcon as u8);
    ocx.flush_jump_context();
    ocx.flush_jump_table_sub_context();
}

pub fn transform_pc_node(mut node_head: *mut NodeHeader, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) {
    // log_to_file("transform_pc_node");
    //dump_memory(ocx.get_root_container_pointer() as *const u8, ocx.get_root_container().size() as usize, ocx).expect("");
    assert_eq!(as_sub_node(node_head).child_container(), PathCompressed);
    assert!(ocx.get_pc_ejection_context().pec_valid);

    if ocx.embedded_traversal_context.embedded_stack.is_none() {
        ocx.embedded_traversal_context.embedded_stack = Some([const { None }; CONTAINER_MAX_EMBEDDED_DEPTH]);
    }

    let child_container_offset: usize = get_offset_child_container(node_head);
    let pc_key_offset: usize = size_of::<PathCompressedNodeHeader>()
        + ocx.get_pc_ejection_context().path_compressed_node_header.value_present() as usize * size_of::<NodeValue>();
    let pc_key_len: usize = ocx.get_pc_ejection_context().path_compressed_node_header.size() - pc_key_offset;
    let container_embedding_limit: u32 = GLOBAL_CONFIG.read().container_embedding_limit;
    let container_embedding_hwm: u32 = GLOBAL_CONFIG.read().header.container_embedding_high_watermark();
    // log_to_file(&format!("offset: {}, key offset: {}, key len: {}", child_container_offset, pc_key_offset, pc_key_len));

    if (ocx.get_root_container().size() >= container_embedding_limit)
        || (ocx.embedded_traversal_context.embedded_container_depth >= CONTAINER_MAX_EMBEDDED_DEPTH)
        || (ocx.embedded_traversal_context.embedded_container_depth > 0
        && ((ocx.embedded_traversal_context.embedded_stack.as_mut().expect(ERR_EMPTY_EMB_STACK)[0]
        .as_mut()
        .expect(ERR_EMPTY_EMB_STACK_POS)
        .borrow_mut()
        .size() as u32)
        >= (container_embedding_hwm - get_container_link_size() as u32)))
    {
        // log_to_file("Trafo1");
        handle_link_transformation(node_head, ocx, ctx, child_container_offset, pc_key_len);
    } else {
        // log_to_file("Trafo2");
        if ocx.embedded_traversal_context.embedded_container_depth == 0 {
            safe_top_node_jump_context(ocx, ctx);
        }

        if pc_key_len == 1 {
            // log_to_file("Trafo2-1");
            let required: usize = size_of::<NodeHeader>() + size_of::<EmbeddedContainer>() - size_of::<PathCompressedNodeHeader>();
            node_head = meta_expand(ocx, ctx, required as u32);
            let child_container: *mut u8 = unsafe { (node_head as *mut u8).add(child_container_offset) };
            unsafe {
                wrap_shift_container(ocx.get_root_container_pointer(), child_container, required);
            }
            update_space(required as i16, ocx, ctx);

            unsafe {
                ocx.embedded_traversal_context.next_embedded_container =
                    NonNull::new((node_head as *mut u8).add(child_container_offset) as *mut EmbeddedContainer);
                let value_present: usize = ocx.get_pc_ejection_context().path_compressed_node_header.value_present() as usize;

                if let Some(next_embedded_container) = ocx.embedded_traversal_context.next_embedded_container {
                    (*next_embedded_container.as_ptr())
                        .set_size((size_of::<EmbeddedContainer>() + size_of::<NodeHeader>() + 1 + value_present * size_of::<NodeValue>()) as u8);
                } else {
                    panic!("{}", ERR_NO_NEXT_CONTAINER)
                }

                /*log_to_file(
                    &format!("new embedded container at key {}; new size calculated: {}, new size set: {}",
                             t, size_of::<EmbeddedContainer>() + size_of::<NodeHeader>() + 1 + value_present * size_of::<NodeValue>(),
                             unsafe { (*(ocx.embedded_traversal_context.next_embedded_container.unwrap().as_ptr())).size() }
                ));*/

                let embedded_top: *mut NodeHeader =
                    (node_head as *mut u8).add(child_container_offset + size_of::<EmbeddedContainer>()) as *mut NodeHeader;
                write_bytes(embedded_top as *mut u8, 0, size_of::<NodeHeader>());

                if ocx.get_pc_ejection_context().path_compressed_node_header.value_present() {
                    as_top_node_mut(embedded_top).set_type_flag(LeafNodeWithValue);
                    copy_nonoverlapping(
                        &mut ocx.get_pc_ejection_context().node_value as *mut NodeValue as *mut u8,
                        (embedded_top as *mut u8).add(size_of::<NodeHeader>() + 1),
                        size_of::<NodeValue>(),
                    );
                } else {
                    as_top_node_mut(embedded_top).set_type_flag(LeafNodeEmpty);
                }
                copy_nonoverlapping(
                    ocx.get_pc_ejection_context().partial_key.as_mut_ptr(),
                    (embedded_top as *mut u8).add(size_of::<NodeHeader>()),
                    1,
                );
            }
        } else if pc_key_len == 2 {
            // log_to_file("Trafo2-2");
            let required: usize = size_of::<NodeHeader>() * 2 + size_of::<EmbeddedContainer>() - size_of::<PathCompressedNodeHeader>();
            node_head = meta_expand(ocx, ctx, required as u32);

            let child_container: *mut u8 = unsafe { (node_head as *mut u8).add(child_container_offset) };
            unsafe {
                wrap_shift_container(ocx.get_root_container_pointer(), child_container, required);
            }

            update_space(required as i16, ocx, ctx);

            unsafe {
                ocx.embedded_traversal_context.next_embedded_container =
                    NonNull::new((node_head as *mut u8).add(child_container_offset) as *mut EmbeddedContainer);
                let value_present = ocx.get_pc_ejection_context().path_compressed_node_header.value_present() as usize;

                if let Some(next_embedded_container) = ocx.embedded_traversal_context.next_embedded_container {
                    (*next_embedded_container.as_ptr()).set_size(
                        (size_of::<EmbeddedContainer>() + (size_of::<NodeHeader>() + 1) * 2 + value_present * size_of::<NodeValue>()) as u8,
                    );
                } else {
                    panic!("{}", ERR_NO_NEXT_CONTAINER)
                }

                /*log_to_file(
                &format!("new embedded container at key {}; new size calculated: {}, new size set: {}",
                         t, size_of::<EmbeddedContainer>() + (size_of::<NodeHeader>() + 1) * 2 + value_present * size_of::<NodeValue>(),
                         unsafe { (*(ocx.embedded_traversal_context.next_embedded_container.unwrap().as_ptr())).size() }
                ));*/

                let embedded_top: *mut NodeHeader =
                    (node_head as *mut u8).add(child_container_offset + size_of::<EmbeddedContainer>()) as *mut NodeHeader;
                write_bytes(embedded_top as *mut u8, 0, size_of::<NodeHeader>());
                as_top_node_mut(embedded_top).set_type_flag(InnerNode);
                copy_nonoverlapping(
                    ocx.get_pc_ejection_context().partial_key.as_mut_ptr(),
                    (embedded_top as *mut u8).add(size_of::<NodeHeader>()),
                    1,
                );

                let embedded_sub: *mut NodeHeader = embedded_top.add(size_of::<NodeHeader>() + 1);
                write_bytes(embedded_sub as *mut u8, 0, 1);
                as_sub_node_mut(embedded_sub).set_container_type(NodeState::SubNode);

                if ocx.get_pc_ejection_context().path_compressed_node_header.value_present() {
                    as_sub_node_mut(embedded_sub).set_type_flag(LeafNodeWithValue);
                    copy_nonoverlapping(
                        &mut ocx.get_pc_ejection_context().node_value as *mut NodeValue as *mut u8,
                        (embedded_sub as *mut u8).add(size_of::<NodeHeader>() + 1),
                        size_of::<NodeValue>(),
                    );
                } else {
                    as_sub_node_mut(embedded_sub).set_type_flag(LeafNodeEmpty);
                }
                copy_nonoverlapping(
                    ocx.get_pc_ejection_context().partial_key.as_mut_ptr().add(1),
                    (embedded_sub as *mut u8).add(size_of::<NodeHeader>()),
                    1,
                );
            }
        } else {
            // log_to_file("Trafo2-3");
            let required: usize = size_of::<NodeHeader>() * 2 + size_of::<EmbeddedContainer>();
            node_head = meta_expand(ocx, ctx, required as u32);

            let child_container: *mut u8 = unsafe { (node_head as *mut u8).add(child_container_offset) };
            unsafe {
                wrap_shift_container(ocx.get_root_container_pointer(), child_container, required);
            }
            update_space(required as i16, ocx, ctx);

            let remaining_partial_key = pc_key_len - 2;
            unsafe {
                ocx.embedded_traversal_context.next_embedded_container =
                    NonNull::new((node_head as *mut u8).add(child_container_offset) as *mut EmbeddedContainer);
                let value_present: usize = ocx.get_pc_ejection_context().path_compressed_node_header.value_present() as usize;

                if let Some(next_embedded_container) = ocx.embedded_traversal_context.next_embedded_container {
                    (*next_embedded_container.as_ptr()).set_size(
                        (size_of::<EmbeddedContainer>()
                            + (size_of::<NodeHeader>() + 1) * 2
                            + value_present * size_of::<NodeValue>()
                            + 1
                            + remaining_partial_key) as u8,
                    );
                } else {
                    panic!("{}", ERR_NO_NEXT_CONTAINER)
                }

                /*log_to_file(
                &format!("new embedded container at key {}; new size calculated: {}, new size set: {}",
                         t, size_of::<EmbeddedContainer>()
                             + (size_of::<NodeHeader>() + 1) * 2
                             + value_present * size_of::<NodeValue>()
                             + 1
                             + remaining_partial_key,
                         unsafe { (*(ocx.embedded_traversal_context.next_embedded_container.unwrap().as_ptr())).size() }
                ));*/

                let embedded_top: *mut NodeHeader =
                    (node_head as *mut u8).add(child_container_offset + size_of::<EmbeddedContainer>()) as *mut NodeHeader;
                write_bytes(embedded_top as *mut u8, 0, size_of::<NodeHeader>());
                as_top_node_mut(embedded_top).set_type_flag(InnerNode);
                copy_nonoverlapping(
                    ocx.get_pc_ejection_context().partial_key.as_mut_ptr(),
                    (embedded_top as *mut u8).add(size_of::<NodeHeader>()),
                    1,
                );

                let embedded_sub: *mut NodeHeader = embedded_top.add(size_of::<NodeHeader>() + 1);
                write_bytes(embedded_sub as *mut u8, 0, 1);
                as_sub_node_mut(embedded_sub).set_container_type(NodeState::SubNode);
                as_sub_node_mut(embedded_sub).set_type_flag(InnerNode);
                copy_nonoverlapping(
                    ocx.get_pc_ejection_context().partial_key.as_mut_ptr().add(1),
                    (embedded_sub as *mut u8).add(size_of::<NodeHeader>()),
                    1,
                );
                as_sub_node_mut(embedded_sub).set_child_container(PathCompressed);

                let pc_node: *mut PathCompressedNodeHeader =
                    (embedded_sub as *mut u8).add(size_of::<NodeHeader>() + 1) as *mut PathCompressedNodeHeader;

                if ocx.get_pc_ejection_context().path_compressed_node_header.value_present() {
                    (*pc_node).set_value_present(true);
                    (*pc_node).set_size(size_of::<PathCompressedNodeHeader>() + size_of::<NodeValue>() + pc_key_len - 2);
                    copy_nonoverlapping(
                        &mut ocx.get_pc_ejection_context().node_value as *mut NodeValue as *mut u8,
                        (pc_node as *mut u8).add(size_of::<PathCompressedNodeHeader>()),
                        size_of::<NodeValue>(),
                    );
                    copy_nonoverlapping(
                        ocx.get_pc_ejection_context().partial_key.as_mut_ptr().add(2),
                        (pc_node as *mut u8).add(size_of::<PathCompressedNodeHeader>() + size_of::<NodeValue>()),
                        pc_key_len - 2,
                    );
                } else {
                    (*pc_node).set_value_present(false);
                    (*pc_node).set_size(size_of::<PathCompressedNodeHeader>() + pc_key_len - 2);
                    copy_nonoverlapping(
                        ocx.get_pc_ejection_context().partial_key.as_mut_ptr().add(2),
                        (pc_node as *mut u8).add(size_of::<PathCompressedNodeHeader>()),
                        pc_key_len - 2,
                    );
                }
            }
        }

        let current_embedded_container_depth = ocx.embedded_traversal_context.embedded_container_depth;

        if let Some(next_embedded_container) = ocx.embedded_traversal_context.next_embedded_container {
            ocx.embedded_traversal_context.embedded_stack.as_mut().expect(ERR_EMPTY_EMB_STACK)[current_embedded_container_depth] =
                Some(AtomicEmbContainer::new_from_pointer(next_embedded_container.as_ptr()));
        } else {
            panic!("{}", ERR_NO_POINTER)
        }
        ocx.embedded_traversal_context.embedded_container_depth += 1;
        // log_to_file(&format!("transform_pc_node set embedded depth to: {}", ocx.embedded_traversal_context.embedded_container_depth));
        ocx.next_container_pointer = None;

        as_sub_node_mut(node_head).set_child_container(ChildLinkType::EmbeddedContainer);
        ocx.path_compressed_ejection_context = None;
        ocx.header.set_next_container_valid(EmbeddedContainerValid);
        ctx.current_container_offset += child_container_offset;
        safe_top_node_jump_context(ocx, ctx);
    }
    //dump_memory(ocx.get_root_container_pointer() as *const u8, ocx.get_root_container().size() as usize, ocx).expect("");
}

/// Inserts a reference key in front of this node header.
///
/// A top node's jump table entry at index i references the key 16 * (i + 1). If this node's key is larger than 16 * (i + 1), this function creates
/// an inner sub node, storing 16 * (i + 1). This value is either stored as absolute key, or as delta encoded key, if the difference betwenn the
/// new sub node and this `node_head` can be delta encoded.
/// # Safety
/// - `node_head` must be a valid, aligned pointer for reading and writing.
pub fn insert_top_jump_table_reference_key(node_head: *mut NodeHeader, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, ref_key: u8) {
    // log_to_file("inject_sublevel_reference_key");
    let diff = ref_key - ctx.last_sub_char_seen;
    let relative = (diff <= DELTA_MAX_VALUE) as usize;
    // log_to_file(&format!("diff: {}, relative: {}", diff, relative));

    // Get either the node's key field or the node's header, depending on if the difference can be delta encoded
    let target = unsafe { (node_head as *mut u8).add(size_of::<NodeHeader>() + (1 - relative)) };

    unsafe {
        let node_offset = (node_head as *mut u8).offset_from(ocx.get_root_container_pointer() as *mut u8) as i32;
        let free_size_left = ocx.get_root_container().free_bytes() as i32;
        let bytes_to_move = ocx.get_root_container().size() as i32 - (node_offset + free_size_left);
        // log_to_file(&format!("offset: {}, free: {}, move: {}", node_offset, free_size_left, bytes_to_move));

        // Shift the entire container's memory starting at this node header by at most 1 byte forward in order to store the reference key
        copy(node_head as *mut u8, target, bytes_to_move as usize);
        write_bytes(node_head as *mut u8, 0, size_of::<NodeHeader>() + 1 - relative);
    }
    as_top_node_mut(node_head).set_type_flag(InnerNode);
    as_top_node_mut(node_head).set_container_type(NodeState::SubNode);

    update_space((size_of::<NodeHeader>() + 1 - relative) as i16, ocx, ctx);
    ctx.second_char = ref_key;

    if relative == 0 {
        // Set the reference key as absolute key
        set_nodes_key(node_head as *mut Node, ocx, ctx, false, ref_key);
    } else {
        // Store the reference key delta encoded
        as_top_node_mut(node_head).set_delta(diff);
        let mut successor: Option<*mut Node> = None;
        let skipped: u32 = get_successor(node_head, &mut successor, ocx, ctx, false);

        if skipped > 0 {
            assert_eq!(
                unsafe { as_top_node(&mut (*(successor.expect(ERR_NO_SUCCESSOR))).header as *mut NodeHeader).container_type() },
                NodeState::SubNode
            );
            let successor_ptr: *mut Node = successor.expect(ERR_NO_SUCCESSOR);
            let succ_delta = unsafe {
                if as_top_node(&mut (*successor_ptr).header as *mut NodeHeader).delta() == 0 {
                    (*successor_ptr).key
                } else {
                    as_top_node(&mut (*successor_ptr).header as *mut NodeHeader).delta()
                }
            };
            update_successor_key(successor_ptr, succ_delta - diff, ref_key, skipped, ocx, ctx);
        }
    }
}
