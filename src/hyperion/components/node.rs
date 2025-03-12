use std::fmt::format;
use crate::hyperion::components::container::update_space_usage;
use crate::hyperion::components::context::{ContainerTraversalContext, JumpContext, KEY_DELTA_STATES};
use crate::hyperion::components::node_header::{as_sub_node, as_top_node, as_top_node_mut, get_successor, NodeHeader};
use crate::hyperion::components::operation_context::OperationContext;
use crate::hyperion::components::return_codes::ReturnCode;
use crate::hyperion::components::return_codes::ReturnCode::OK;
use std::ptr::{copy, write_bytes};
use crate::hyperion::internals::core::log_to_file;

#[derive(Debug, PartialEq)]
pub enum NodeType {
    Invalid = 0,
    InnerNode = 1,
    LeafNodeEmpty = 2,
    LeafNodeWithValue = 3
}

impl NodeType {
    /// Transforms its states into a 2 bit representation.
    pub(crate) const fn into_bits(self) -> u8 {
        self as _
    }

    /// Transforms its states from an 8 bit value into a named state.
    ///
    /// # Panics
    /// Panics if an invalid node type was found.
    pub(crate) const fn from_bits(value: u8) -> Self {
        match value {
            0 => NodeType::Invalid,
            1 => NodeType::InnerNode,
            2 => NodeType::LeafNodeEmpty,
            3 => NodeType::LeafNodeWithValue,
            _ => panic!("Use of undefined node type")
        }
    }
}

pub struct NodeValue {
    pub v: u64
}

#[repr(C)]
pub struct Node {
    pub header: NodeHeader,
    pub stored_value: u8
}

// OK
pub fn get_top_node_key(node: *mut Node, container_traversal_context: &mut ContainerTraversalContext) -> u8 {
    if as_top_node(unsafe {&mut (*node).header}).delta() == 0 {
        if container_traversal_context.header.last_top_char_set() {
            return container_traversal_context.last_top_char_seen + unsafe { (*node).stored_value };
        }
        return unsafe { (*node).stored_value };
    }
    container_traversal_context.last_top_char_seen + as_top_node(unsafe {&mut (*node).header}).delta()
}

// OK
// (TODO comment) force = true äquivalent zu get_subnodes_key2
pub fn get_sub_node_key(node: *mut Node, container_traversal_context: &mut ContainerTraversalContext, force: bool) -> u8 {
    if force || container_traversal_context.header.last_sub_char_set() {
        if as_sub_node(unsafe {&mut (*node).header}).has_delta() {
            return container_traversal_context.last_sub_char_seen + as_sub_node(unsafe {&mut (*node).header}).delta();
        }
        return container_traversal_context.last_sub_char_seen + unsafe { (*node).stored_value };
    }
    unsafe { (*node).stored_value }
}

fn calculate_stored_value(node: *mut Node, ctx: &mut ContainerTraversalContext) -> u8 {
    match as_top_node(unsafe { &mut (*node).header }).container_type() {
        0 if ctx.header.last_top_char_set() => ctx.first_char - ctx.last_top_char_seen,
        0 => ctx.first_char,
        _ if ctx.header.last_sub_char_set() => ctx.second_char - ctx.last_sub_char_seen,
        _ => ctx.second_char
    }
}

fn get_successor_node(node: *mut Node, successor_ptr: &mut Option<*mut Node>, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, embedded: bool) -> u32 {
    if embedded {
        get_successor(unsafe { &mut (*node).header }, successor_ptr, ocx, ctx, true)
    }
    else {
        get_successor(unsafe { &mut (*node).header }, successor_ptr, ocx, ctx, false)
    }
}

fn get_stored_value(node: *mut Node) -> u8 {
    if as_top_node(unsafe { &mut (*node).header }).delta() == 0 {
        unsafe { (*node).stored_value }
    }
    else {
        as_top_node(unsafe { &mut (*node).header }).delta()
    }
}

fn calculate_delta_difference(node: *mut Node, successor: *mut Node) -> u8 {
    let succ_delta: u8 = get_stored_value(successor);
    let this_delta: u8 = get_stored_value(node);
    succ_delta - this_delta
}

// OK
pub fn set_nodes_key2(node: *mut Node, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, embedded: bool, absolute_key: u8) -> ReturnCode {
    assert_eq!(unsafe { (*node).stored_value }, 0);
    as_top_node_mut(unsafe { &mut (*node).header }).set_delta(0);

    unsafe { (*node).stored_value = calculate_stored_value(node, ctx); }
    log_to_file(&format!("set_nodes_key2: {}", unsafe { (*node).stored_value }));


    let mut successor_ptr: Option<*mut Node> = None;

    let skipped_bytes: u32 = get_successor_node(node, &mut successor_ptr, ocx, ctx, embedded);

    if let Some(successor) = successor_ptr.filter(|_| skipped_bytes > 0) {
        let diff = calculate_delta_difference(node, successor);
        update_successor_key(successor, diff, absolute_key + diff, skipped_bytes, ocx, ctx);
    }

    OK
}

fn update_stored_value_from_diff(node: *mut Node, diff: u8) -> bool {
    if diff as usize > KEY_DELTA_STATES {
        unsafe { (*node).stored_value = diff; }
        return true;
    }

    if as_top_node(unsafe { &mut (*node).header }).delta() > 0 {
        as_top_node_mut(unsafe { &mut (*node).header }).set_delta(diff);
        return true;
    }
    as_top_node_mut(unsafe { &mut (*node).header }).set_delta(diff);
    false
}

fn adjust_memory_allocation(node: *mut Node, skipped: u32, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) {
    let free_size_left: u8 = ocx.get_root_container().free_bytes();
    let remaining: u32 = ocx.get_root_container().size()
        - (ocx.embedded_traversal_context.next_embedded_container_offset as u32
        + ctx.current_container_offset as u32 + skipped + 2 + free_size_left as u32);

    unsafe {
        copy(node.add(size_of::<NodeHeader>() + 1) as *mut u8, node.add(size_of::<NodeHeader>()) as *mut u8, remaining as usize);
        write_bytes(node.add(size_of::<NodeHeader>()) as *mut u8, 0, 1);
    }
}

fn handle_jump_context(node: *mut Node, diff: u8, absolute_key: u8, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) {
    if ocx.embedded_traversal_context.embedded_container_depth > 0 {
        let current_jump_context: JumpContext = ocx.jump_context.duplicate();
        update_space_usage(-1, ocx, ctx);
        ocx.jump_context = current_jump_context;
    }
    else if as_top_node(unsafe { &mut (*node).header }).container_type() == 0 {
        if ocx.jump_context.top_node_key < 255 {
            let current_jump_context: JumpContext = ocx.jump_context.duplicate();
            ocx.jump_context.predecessor = Some(node as *mut NodeHeader);

            ocx.jump_context.sub_nodes_seen = 0;
            ocx.jump_context.top_node_predecessor_offset_absolute = unsafe {
                ((&mut (*node).header) as *mut NodeHeader as *mut u8).offset_from(ocx.get_root_container_pointer() as *mut u8) as i32
            };
            let last_key_seen: i32 = ocx.jump_context.top_node_key;
            ocx.jump_context.top_node_key = absolute_key as i32;
            update_space_usage(-1, ocx, ctx);
            ocx.jump_context.top_node_key = last_key_seen;
            ocx.jump_context = current_jump_context;
        }
    }
    else {
        let last_key_seen: u8 = ctx.second_char;
        ctx.second_char += diff;
        update_space_usage(-1, ocx, ctx);
        ctx.second_char = last_key_seen;
    }
}

// OK
pub fn update_successor_key(node: *mut Node, diff: u8, absolute_key: u8, skipped: u32, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) -> ReturnCode {
    let ret: bool = update_stored_value_from_diff(node, diff);
    if ret { return OK; }

    adjust_memory_allocation(node, skipped, ocx, ctx);
    handle_jump_context(node, diff, absolute_key, ocx, ctx);
    OK
}
