use crate::hyperion::components::context::{ContainerTraversalContext, OperationContext};
use crate::hyperion::components::node_header::{get_successor, get_successor_embedded, NodeHeader};
use crate::hyperion::components::return_codes::ReturnCode;
use crate::hyperion::components::return_codes::ReturnCode::OK;

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
        let mut successor_ptr: Option<Box<Node>> = None;

        if self.header.as_top_node().container_type() == 0 {
            if ctx.header.last_top_char_set() {
                self.stored_value = ctx.first_char - ctx.header.last_top_char_set() as u8;
            }
            else {
                self.stored_value = ctx.first_char;
            }
        }
        else {
            if ctx.header.last_sub_char_set() {
                self.stored_value = ctx.second_char - ctx.header.last_sub_char_set() as u8;
            }
            else {
                self.stored_value = ctx.second_char;
            }
        }

        let skipped_bytes: u32 = if embedded {
            get_successor_embedded(&mut self.header as *mut NodeHeader, &mut successor_ptr, ocx, ctx) as u32
        }
        else {
            get_successor(&mut self.header as *mut NodeHeader, &mut successor_ptr, ocx, ctx) as u32
        };

        if skipped_bytes > 0 {
            let successor: &mut Box<Node> = successor_ptr.as_mut().unwrap();
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
            update_successor_key(successor.as_mut() as *mut Node, diff, absolute_key + diff, skipped_bytes, ocx, ctx);
        }
        OK
    }
}

pub fn update_successor_key(node: *mut Node, diff: u8, absolute_key: u8, skipped: u32, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) -> ReturnCode {
    todo!()
}
