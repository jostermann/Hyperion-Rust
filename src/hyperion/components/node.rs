use crate::hyperion::components::container::Container;
use crate::hyperion::components::context::{ContainerTraversalContext, EmbeddedTraversalContext, JumpContext, OperationContext, KEY_DELTA_STATES};
use crate::hyperion::components::node_header::{get_successor, get_successor_embedded, NodeHeader};
use crate::hyperion::components::return_codes::ReturnCode;
use crate::hyperion::components::return_codes::ReturnCode::OK;
use std::ffi::c_void;
use std::ptr::{copy, write_bytes, NonNull};

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
    pub fn get_top_node_key(&self, container_traversal_context: &mut ContainerTraversalContext) -> u8 {
        if container_traversal_context.header.last_top_char_set() {
            if self.header.as_top_node().has_delta() {
                return container_traversal_context.last_top_char_seen + self.header.as_top_node().delta();
            }
            return container_traversal_context.last_top_char_seen + self.stored_value;
        }
        self.stored_value
    }

    // (TODO comment) force = true äquivalent zu get_subnodes_key2
    pub fn get_sub_node_key(&self, container_traversal_context: &mut ContainerTraversalContext, force: bool) -> u8 {
        if force || container_traversal_context.header.last_sub_char_set() {
            if self.header.as_sub_node().has_delta() {
                return container_traversal_context.last_sub_char_seen + self.header.as_sub_node().delta();
            }
            return container_traversal_context.last_sub_char_seen + self.stored_value;
        }
        self.stored_value
    }

    pub fn set_nodes_key2(&mut self, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, embedded: bool, absolute_key: u8) -> ReturnCode {
        assert_eq!(self.stored_value, 0);
        self.header.as_top_node_mut().set_delta(0);
        let mut successor_ptr: Option<NonNull<Node>> = None;

        if self.header.as_top_node().container_type() == 0 {
            if ctx.header.last_top_char_set() {
                self.stored_value = ctx.first_char - ctx.header.last_top_char_set() as u8;
            }
            else {
                self.stored_value = ctx.first_char;
            }
        }
        else if ctx.header.last_sub_char_set() {
            self.stored_value = ctx.second_char - ctx.header.last_sub_char_set() as u8;
        }
        else {
            self.stored_value = ctx.second_char;
        }

        let skipped_bytes: u32 = if embedded {
            get_successor_embedded(&mut self.header as *mut NodeHeader, &mut successor_ptr, ocx, ctx)
        }
        else {
            get_successor(&mut self.header as *mut NodeHeader, &mut successor_ptr, ocx, ctx)
        };

        if skipped_bytes > 0 {
            let successor: &mut Node = unsafe { successor_ptr.as_mut().unwrap().as_mut() };
            let succ_delta: u8 =  if successor.header.as_top_node().delta() == 0 {
                successor.stored_value
            }
            else {
                successor.header.as_top_node().delta()
            };
            let this_delta: u8 = if self.header.as_top_node().delta() == 0 {
                self.stored_value
            }
            else {
                self.header.as_top_node().delta()
            };
            let diff: u8 = succ_delta - this_delta;
            update_successor_key(successor as *mut Node, diff, absolute_key + diff, skipped_bytes, ocx, ctx);
        }
        OK
    }
}

pub fn update_successor_key(node: *mut Node, diff: u8, absolute_key: u8, skipped: u32, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) -> ReturnCode {
    if diff as usize > KEY_DELTA_STATES {
        unsafe { (*node).stored_value = diff; }
    }
    else {
        let node_ref: &mut Node = unsafe { node.as_mut().unwrap() };

        if node_ref.header.as_top_node().delta() > 0 {
            node_ref.header.as_top_node_mut().set_delta(diff);
            return OK;
        }

        node_ref.header.as_top_node_mut().set_delta(diff);
        let mut emb_ctx: EmbeddedTraversalContext = ocx.embedded_traversal_context.take().unwrap();
        let free_size_left: u8 = emb_ctx.root_container.as_mut().free_bytes();
        let remaining: u32 = emb_ctx.root_container.as_mut().size() - (emb_ctx.next_embedded_container_offset as u32 + ctx.current_container_offset as u32 + skipped + 2 + free_size_left as u32);
        unsafe {
            copy((node as *mut u8).add(size_of::<NodeHeader>() + 1),(node as *mut u8).add(size_of::<NodeHeader>()), remaining as usize);
            write_bytes((node as *mut u8).add(size_of::<NodeHeader>()), 0, 1);
        }

        if emb_ctx.embedded_container_depth > 0 {
            let current_jump_context: JumpContext = ocx.jump_context.as_mut().unwrap().duplicate();
            emb_ctx.root_container.as_mut().update_space_usage(-1, ocx, ctx);
            ocx.jump_context = Some(current_jump_context);
        }
        else if node_ref.header.as_top_node().container_type() == 0 {
            if ocx.jump_context.as_mut().unwrap().top_node_key < 255 {
                let current_jump_context: JumpContext = ocx.jump_context.as_mut().unwrap().duplicate();
                ocx.jump_context.as_mut().unwrap().predecessor = unsafe {
                    Some(
                        Box::from_raw(node.as_mut().unwrap() as *mut Node as *mut NodeHeader)
                    )
                };

                ocx.jump_context.as_mut().unwrap().sub_nodes_seen = 0;
                ocx.jump_context.as_mut().unwrap().top_node_predecessor_offset_absolute = unsafe {
                    ((&mut (*node).header) as *mut NodeHeader as *mut c_void).offset_from(ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut() as *mut Container as *mut c_void) as i32
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
