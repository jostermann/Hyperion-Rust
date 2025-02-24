use crate::hyperion::components::context::{ContainerTraversalContext, OperationContext};
use crate::hyperion::components::node_header::NodeHeader;

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
        if container_traversal_context.header.last_top_char_set() == 1 {
            if self.header.as_top_node().has_delta() {
                return container_traversal_context.last_top_char_seen + self.header.as_top_node().delta();
            }
            return container_traversal_context.last_top_char_seen + self.stored_value;
        }
        self.stored_value
    }

    // (TODO comment) force = true äquivalent zu get_subnodes_key2
    pub fn get_sub_node_key(&self, container_traversal_context: &mut ContainerTraversalContext, force: bool) -> u8 {
        if force || container_traversal_context.header.last_sub_char_set() == 1 {
            if self.header.as_sub_node().has_delta() {
                return container_traversal_context.last_sub_char_seen + self.header.as_sub_node().delta();
            }
            return container_traversal_context.last_sub_char_seen + self.stored_value;
        }
        self.stored_value
    }
}
