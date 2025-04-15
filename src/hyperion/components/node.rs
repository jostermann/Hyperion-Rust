use crate::hyperion::components::container::update_space;
use crate::hyperion::components::context::{ContainerTraversalContext, JumpContext, DELTA_MAX_VALUE};
use crate::hyperion::components::node_header::{as_sub_node, as_top_node, as_top_node_mut, get_successor, NodeHeader};
use crate::hyperion::components::operation_context::OperationContext;
use crate::hyperion::components::return_codes::ReturnCode;
use crate::hyperion::components::return_codes::ReturnCode::OK;
use crate::hyperion::internals::core::log_to_file;
use std::ptr::{copy, write_bytes};

/// All node types possible in the trie.
#[derive(Debug, PartialEq)]
pub enum NodeType {
    /// Invalid nodes reference to all-zeroed memory and are not created yet.
    Invalid = 0,
    /// An inner node has at least one sub node as child node.
    InnerNode = 1,
    /// An empty leaf node is a node without stored `NodeValue`. This node type simply terminates a path in the trie, without referring to a stored value.
    LeafNodeEmpty = 2,
    /// A leaf node with value terminates the path in the trie and stores a `NodeValue`.
    LeafNodeWithValue = 3,
}

impl NodeType {
    /// Transforms its states into a 2 bit representation.
    pub(crate) const fn into_bits(self) -> u8 {
        self as _
    }

    /// Transforms its states from an 8 bit value into a named state.
    ///
    /// # Panics
    /// - if an invalid node type was found.
    pub(crate) const fn from_bits(value: u8) -> Self {
        match value {
            0 => NodeType::Invalid,
            1 => NodeType::InnerNode,
            2 => NodeType::LeafNodeEmpty,
            3 => NodeType::LeafNodeWithValue,
            _ => panic!("Use of undefined node type"),
        }
    }
}

/// All nodes states defined by the hyperion data structure.
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum NodeState {
    /// References a top node.
    TopNode = 0,
    /// References a sub node.
    SubNode = 1,
}

impl NodeState {
    /// Transforms its states into a 1 bit representation.
    pub(crate) const fn into_bits(self) -> u8 {
        self as _
    }

    /// Transforms its states from an 8 bit value into a named state.
    ///
    /// # Panics
    /// - if an invalid node type was found.
    pub(crate) const fn from_bits(value: u8) -> Self {
        match value {
            0 => NodeState::TopNode,
            1 => NodeState::SubNode,
            _ => panic!("Use of undefined node state"),
        }
    }
}

/// A node value is stored by `LeafNodeWithValue`. The leaf node terminates the current path in the trie and the node value stored its referenced value.
#[repr(C)]
pub struct NodeValue {
    pub value: u64,
}

/// A generic node, storing a node header and the nodes value.
#[repr(C)]
pub struct Node {
    /// Header stores a generic node header, which can be either a top node or a sub node. Since both node headers are equally sized, any calls
    /// to top or sub nodes can be used interchangeably.
    ///
    /// See [`crate::hyperion::components::node_header`] for related operations on the node header.
    pub header: NodeHeader,
    /// The stored 8-bit partial key of this node.
    pub key: u8,
}

/// Returns the nodes key in respect of its delta encoding and the current container traversal context.
///
/// # Returns
/// - The nodes raw key if the node is not delta encoded.
/// - The nodes implicitly stored key using its delta encoding and the last top char seen.
/// - The key resulting from the nodes stored key and the last top nodes key seen, if present.
/// # Safety
/// `node` must be a valid, aligned pointer for reading.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn get_top_node_key(node: *mut Node, ctx: &mut ContainerTraversalContext) -> u8 {
    if as_top_node(unsafe { &mut (*node).header }).delta() == 0 {
        if ctx.header.last_top_char_set() {
            return ctx.last_top_char_seen + unsafe { (*node).key };
        }
        return unsafe { (*node).key };
    }
    ctx.last_top_char_seen + as_top_node(unsafe { &mut (*node).header }).delta()
}

/// Returns the nodes key in respect of its delta encoding and the current container traversal context.
///
/// `force` default to false. A `force` value of `true` will include the last sub nodes key seen, regardless if it was set or not.
///
/// # Returns
/// - The nodes raw key if the node is not delta encoded.
/// - The nodes implicitly stored key using its delta encoding and the last sub char seen.
/// - The key resulting from the nodes stored key and the last sub nodes key seen, if present.
/// # Safety
/// `node` must be a valid, aligned pointer for reading.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn get_sub_node_key(node: *mut Node, ctx: &mut ContainerTraversalContext, force: bool) -> u8 {
    if force || ctx.header.last_sub_char_set() {
        if as_sub_node(unsafe { &mut (*node).header }).has_delta() {
            return ctx.last_sub_char_seen + as_sub_node(unsafe { &mut (*node).header }).delta();
        }
        return ctx.last_sub_char_seen.wrapping_add(unsafe { (*node).key });
    }
    unsafe { (*node).key }
}

/// Using the container traversal context, returns the key to be stored in the given `node`.
/// # Safety
// `node` must be a valid, aligned pointer for reading.
fn calculate_stored_value(node: *mut Node, ctx: &mut ContainerTraversalContext) -> u8 {
    match as_top_node(unsafe { &mut (*node).header }).container_type() {
        NodeState::TopNode if ctx.header.last_top_char_set() => ctx.first_char - ctx.last_top_char_seen,
        NodeState::TopNode => ctx.first_char,
        _ if ctx.header.last_sub_char_set() => ctx.second_char - ctx.last_sub_char_seen,
        _ => ctx.second_char,
    }
}

/// Returns the stored key in its raw form or in its delta encoded state.
/// # Safety
// `node` must be a valid, aligned pointer for reading.
fn get_stored_value(node: *mut Node) -> u8 {
    if as_top_node(unsafe { &mut (*node).header }).delta() == 0 {
        unsafe { (*node).key }
    } else {
        as_top_node(unsafe { &mut (*node).header }).delta()
    }
}

/// Calculates the delta difference between the successor nodes key and the nodes key.
/// # Safety
/// - `node` must be a valid, aligned pointer for reading.
/// - `successor` must be a valid, aligned pointer for reading.
fn calculate_delta_difference(node: *mut Node, successor: *mut Node) -> u8 {
    let succ_delta: u8 = get_stored_value(successor);
    let this_delta: u8 = get_stored_value(node);
    // log_to_file(&format!("set_nodes_key2: succ_delta: {}, this_delta: {}, diff: {}", succ_delta, this_delta, succ_delta.wrapping_sub(this_delta)));
    succ_delta.wrapping_sub(this_delta)
}

/// Sets the given nodes key from the current [`ContainerTraversalContext`].
///
/// This function resets the nodes delta encoding, calculates the nodes key from the current [`ContainerTraversalContext`] and updates the successor
/// node from the absolute key, if present.
///
/// # Safety
/// - `node` must be a valid, aligned pointer for reading and writing.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn set_nodes_key(
    node: *mut Node, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, embedded: bool, absolute_key: u8,
) -> ReturnCode {
    assert_eq!(unsafe { (*node).key }, 0);
    as_top_node_mut(unsafe { &mut (*node).header }).set_delta(0);

    unsafe {
        (*node).key = calculate_stored_value(node, ctx);
    }

    let mut successor_ptr: Option<*mut Node> = None;
    let skipped_bytes: u32 = get_successor(unsafe { &mut (*node).header }, &mut successor_ptr, ocx, ctx, embedded);

    if let Some(successor) = successor_ptr.filter(|_| skipped_bytes > 0) {
        let diff: u8 = calculate_delta_difference(node, successor);
        update_successor_key(successor, diff, absolute_key.wrapping_add(diff), skipped_bytes, ocx, ctx);
    }
    // log_to_file(&format!("set_nodes_key2: {}", unsafe { (*node).key }));

    OK
}

/// Updates the nodes key from the given delta difference.
///
/// # Returns
/// - `true`, if the difference was successfully stored in the key or delta field.
/// - `false`, if further updates are successful. This will occur, when the difference must be stored as delta, but the delta field was 0.
/// # Safety
/// - `node` must be a valid, aligned pointer for reading and writing.
fn update_stored_value_from_diff(node: *mut Node, diff: u8) -> bool {
    if diff > DELTA_MAX_VALUE {
        // The difference is numerically greater than can be represented in 3 bits
        // Store the difference as raw key
        unsafe {
            (*node).key = diff;
        }
        return true;
    }

    if as_top_node(unsafe { &mut (*node).header }).delta() > 0 {
        as_top_node_mut(unsafe { &mut (*node).header }).set_delta(diff);
        return true;
    }
    as_top_node_mut(unsafe { &mut (*node).header }).set_delta(diff);
    false
}

/// Adjusts the containers memory after inserting a delta encoding on this [`Node`].
///
/// Since the node will be delta encoded, only the header must be stored. This function overwrites the previously stored key and shifts the complete
/// container one byte backwards beginning behind the nodes key.
/// # Safety
/// - `node` must be a valid, aligned pointer for reading and writing.
fn adjust_memory_allocation(node: *mut Node, skipped: u32, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) {
    let free_bytes: u8 = ocx.get_root_container().free_bytes();
    let trailing_bytes: u32 = ocx.get_root_container().size()
        - (ocx.embedded_traversal_context.next_embedded_container_offset as u32
        + ctx.current_container_offset as u32
        + skipped
        + 2
        + free_bytes as u32);
    // node_ptr points to the start of the nodes head: | node head (1 B) | key (1 B) | other
    let node_ptr: *mut u8 = node as *mut u8;

    unsafe {
        // shift the container one byte backwards
        // e.g., | node head (1 B) | key (1 B) | other -----> | node head (1 B) | other
        copy(node_ptr.add(size_of::<NodeHeader>() + 1), node_ptr.add(size_of::<NodeHeader>()), trailing_bytes as usize);
        // zero all memory that is now unused
        write_bytes(node_ptr.add(size_of::<NodeHeader>() + trailing_bytes as usize), 0, 1);
    }
}

/// Updates the containers space and jump properties after shift-overwriting the nodes key.
/// # Safety
/// - `node` must be a valid, aligned pointer for reading and writing.
fn handle_jump_context(node: *mut Node, diff: u8, absolute_key: u8, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) {
    if ocx.embedded_traversal_context.embedded_container_depth > 0 {
        // Store the current jump context, increase the containers space properties by 1 byte and restore the old jump context
        let current_jump_context: JumpContext = ocx.jump_context.duplicate();
        update_space(-1, ocx, ctx);
        ocx.jump_context = current_jump_context;
    } else if as_top_node(unsafe { &mut (*node).header }).container_type() == NodeState::TopNode && ocx.jump_context.top_node_key < 255 {
        // Store the current node in the jump context
        // The update_space function will automatically update the jump tables, if necessary
        let current_jump_context: JumpContext = ocx.jump_context.duplicate();
        ocx.jump_context.predecessor = Some(node as *mut NodeHeader);

        ocx.jump_context.sub_nodes_seen = 0;
        ocx.jump_context.top_node_predecessor_offset_absolute =
            unsafe { ((&mut (*node).header) as *mut NodeHeader as *mut u8).offset_from(ocx.get_root_container_pointer() as *mut u8) as i32 };
        let last_key_seen: i32 = ocx.jump_context.top_node_key;
        ocx.jump_context.top_node_key = absolute_key as i32;
        update_space(-1, ocx, ctx);
        ocx.jump_context.top_node_key = last_key_seen;
        ocx.jump_context = current_jump_context;
    } else {
        // jump-free update: update the containers space, and restore the old second char
        let last_key_seen: u8 = ctx.second_char;
        ctx.second_char += diff;
        update_space(-1, ocx, ctx);
        ctx.second_char = last_key_seen;
    }
}

/// Updates this nodes key using the given delta difference.
///
/// This function can be called after inserting a predecessor node. Using the specified delta difference and absolute key, the function will
/// update this nodes key, potentially insert a delta encoding, update the containers memory and alle jump tables.
/// # Safety
/// - `node` must be a valid, aligned pointer for reading and writing.
pub fn update_successor_key(
    node: *mut Node, diff: u8, absolute_key: u8, skipped: u32, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext,
) -> ReturnCode {
    // log_to_file(&format!("update successor key: {}, {}", absolute_key, diff));
    let ret: bool = update_stored_value_from_diff(node, diff);
    if ret {
        // 1.) The difference could not be delta encoded and was stored as a raw key in this node.
        // 2.) This node was previously delta encoded and the delta-value was updated.
        return OK;
    }

    // The difference can be delta encoded, but this node was not delta encoded before
    adjust_memory_allocation(node, skipped, ocx, ctx);
    handle_jump_context(node, diff, absolute_key, ocx, ctx);
    OK
}

#[cfg(test)]
mod test_node {
    use crate::hyperion::components::node::{Node, NodeState, NodeType};
    use crate::hyperion::components::node_header::NodeHeader;
    use crate::hyperion::components::top_node::TopNode;

    #[test]
    fn test_node_size() {
        let node_header = NodeHeader::new_top_node(
            TopNode::new()
                .with_type_flag(NodeType::InnerNode)
                .with_container_type(NodeState::TopNode)
                .with_delta(0b110)
                .with_jump_table_present(false)
                .with_jump_successor_present(false),
        );

        let node = Node {
            header: node_header,
            key: 116,
        };

        assert_eq!(size_of_val(&node.key), 1);
        assert_eq!(size_of_val(&node.header), 1);
        assert_eq!(size_of_val(&node), 2);

        assert_eq!(node.key, 116);
    }
}
