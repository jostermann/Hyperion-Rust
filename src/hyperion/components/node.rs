use crate::hyperion::components::context::{ContainerTraversalContext, EmbeddedTraversalContext, JumpContext, KEY_DELTA_STATES};
use crate::hyperion::components::node_header::{as_sub_node, as_top_node, as_top_node_mut, get_successor, get_successor_embedded, NodeHeader};
use crate::hyperion::components::return_codes::ReturnCode;
use crate::hyperion::components::return_codes::ReturnCode::OK;
use std::ffi::c_void;
use std::ptr::{copy, write_bytes, NonNull};
use crate::hyperion::components::operation_context::OperationContext;

#[derive(Debug, PartialEq, PartialOrd)]
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

pub struct Node {
    pub header: NodeHeader,
    pub stored_value: u8
}

impl Node {

}

pub fn get_top_node_key(node: *mut Node, container_traversal_context: &mut ContainerTraversalContext) -> u8 {
    let node_ref: &mut Node = unsafe { node.as_mut().unwrap() };
    if container_traversal_context.header.last_top_char_set() {
        if as_top_node(&mut node_ref.header as *mut NodeHeader).has_delta() {
            return container_traversal_context.last_top_char_seen + as_top_node(&mut node_ref.header as *mut NodeHeader).delta();
        }
        return container_traversal_context.last_top_char_seen + node_ref.stored_value;
    }
    node_ref.stored_value
}

// (TODO comment) force = true äquivalent zu get_subnodes_key2
pub fn get_sub_node_key(node: *mut Node, container_traversal_context: &mut ContainerTraversalContext, force: bool) -> u8 {
    let node_ref: &mut Node = unsafe { node.as_mut().unwrap() };
    if force || container_traversal_context.header.last_sub_char_set() {
        if as_sub_node(&mut node_ref.header as *mut NodeHeader).has_delta() {
            return container_traversal_context.last_sub_char_seen + as_sub_node(&mut node_ref.header as *mut NodeHeader).delta();
        }
        return container_traversal_context.last_sub_char_seen + node_ref.stored_value;
    }
    node_ref.stored_value
}

pub fn set_nodes_key2(node: *mut Node, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, embedded: bool, absolute_key: u8) -> ReturnCode {
    let node_ref: &mut Node = unsafe { node.as_mut().unwrap() };
    assert_eq!(node_ref.stored_value, 0);
    as_top_node_mut(&mut node_ref.header as *mut NodeHeader).set_delta(0);
    let mut successor_ptr: Option<NonNull<Node>> = None;

    if as_top_node(&mut node_ref.header as *mut NodeHeader).container_type() == 0 {
        if ctx.header.last_top_char_set() {
            node_ref.stored_value = ctx.first_char - ctx.header.last_top_char_set() as u8;
        }
        else {
            node_ref.stored_value = ctx.first_char;
        }
    }
    else if ctx.header.last_sub_char_set() {
        node_ref.stored_value = ctx.second_char - ctx.header.last_sub_char_set() as u8;
    }
    else {
        node_ref.stored_value = ctx.second_char;
    }

    let skipped_bytes: u32 = if embedded {
        get_successor_embedded(node as *mut NodeHeader, &mut successor_ptr, ocx, ctx)
    }
    else {
        get_successor(node as *mut NodeHeader, &mut successor_ptr, ocx, ctx)
    };

    if skipped_bytes > 0 {
        let successor: &mut Node = unsafe { successor_ptr.as_mut().unwrap().as_mut() };
        let succ_delta: u8 =  if as_top_node(&mut successor.header as *mut NodeHeader).delta() == 0 {
            successor.stored_value
        }
        else {
            as_top_node(&mut successor.header as *mut NodeHeader).delta()
        };
        let this_delta: u8 = if as_top_node(&mut node_ref.header as *mut NodeHeader).delta() == 0 {
            node_ref.stored_value
        }
        else {
            as_top_node(&mut node_ref.header as *mut NodeHeader).delta()
        };
        let diff: u8 = succ_delta - this_delta;
        update_successor_key(successor as *mut Node, diff, absolute_key + diff, skipped_bytes, ocx, ctx);
    }
    OK
}

pub fn update_successor_key(node: *mut Node, diff: u8, absolute_key: u8, skipped: u32, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) -> ReturnCode {
    if diff as usize > KEY_DELTA_STATES {
        unsafe { (*node).stored_value = diff; }
    }
    else {
        let node_ref: &mut Node = unsafe { node.as_mut().unwrap() };

        if as_top_node(&mut node_ref.header as *mut NodeHeader).delta() > 0 {
            as_top_node_mut(&mut node_ref.header).set_delta(diff);
            return OK;
        }

        as_top_node_mut(&mut node_ref.header).set_delta(diff);
        let mut emb_ctx: EmbeddedTraversalContext = ocx.embedded_traversal_context.take().unwrap();
        let free_size_left: u8 = emb_ctx.root_container.as_mut().free_bytes();
        let remaining: u32 = emb_ctx.root_container.as_mut().size() - (emb_ctx.next_embedded_container_offset as u32 + ctx.current_container_offset as u32 + skipped + 2 + free_size_left as u32);
        unsafe {
            copy(node.add(size_of::<NodeHeader>() + 1) as *mut u8, node.add(size_of::<NodeHeader>()) as *mut u8, remaining as usize);
            write_bytes(node.add(size_of::<NodeHeader>()) as *mut u8, 0, 1);
        }

        if emb_ctx.embedded_container_depth > 0 {
            let current_jump_context: JumpContext = ocx.jump_context.as_mut().unwrap().duplicate();
            emb_ctx.root_container.as_mut().update_space_usage(-1, ocx, ctx);
            ocx.jump_context = Some(current_jump_context);
        }
        else if as_top_node(&mut node_ref.header as *mut NodeHeader).container_type() == 0 {
            if ocx.jump_context.as_mut().unwrap().top_node_key < 255 {
                let current_jump_context: JumpContext = ocx.jump_context.as_mut().unwrap().duplicate();
                ocx.jump_context.as_mut().unwrap().predecessor = unsafe {
                    Some(
                        Box::from_raw(node.as_mut().unwrap() as *mut Node as *mut NodeHeader)
                    )
                };

                ocx.jump_context.as_mut().unwrap().sub_nodes_seen = 0;
                ocx.jump_context.as_mut().unwrap().top_node_predecessor_offset_absolute = unsafe {
                    ((&mut (*node).header) as *mut NodeHeader as *mut c_void).offset_from(ocx.get_root_container_pointer() as *mut c_void) as i32
                };
                let last_key_seen: i32 = ocx.jump_context.as_mut().unwrap().top_node_key;
                ocx.jump_context.as_mut().unwrap().top_node_key = absolute_key as i32;
                let mut emb_ctx: EmbeddedTraversalContext = ocx.embedded_traversal_context.take().unwrap();
                emb_ctx.root_container.as_mut().update_space_usage(-1, ocx, ctx);
                ocx.embedded_traversal_context = Some(emb_ctx);
                ocx.jump_context.as_mut().unwrap().top_node_key = last_key_seen;
                ocx.jump_context = Some(current_jump_context);
            }
        }
        else {
            let last_key_seen: u8 = ctx.second_char;
            ctx.second_char += diff;
            emb_ctx.root_container.as_mut().update_space_usage(-1, ocx, ctx);
            ctx.second_char = last_key_seen;
        }
        ocx.embedded_traversal_context = Some(emb_ctx);
    }
    OK
}
