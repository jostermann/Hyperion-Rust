use bitfield_struct::bitfield;

use crate::hyperion::components::node::{NodeState, NodeType};

/// Stores all child link types possible.
#[derive(Debug, PartialOrd, PartialEq, Eq, Ord)]
pub enum ChildLinkType {
    /// The corresponding node is not linked and is either a lead node or currently "free floating" in memory.
    None = 0,
    /// The corresponding node is followed by a hyperion pointer to the child container.
    Link = 1,
    /// The corresponding node is followed by an embedded container.
    EmbeddedContainer = 2,
    /// The child node is path compressed.
    PathCompressed = 3,
}

impl ChildLinkType {
    /// Transforms its states into a 2 bit representation.
    pub(crate) const fn into_bits(self) -> u8 {
        self as _
    }

    /// Transforms its states from an 8 bit value into a named state.
    ///
    /// # Panics
    /// Panics if an invalid link type was found.
    pub(crate) const fn from_bits(value: u8) -> Self {
        match value {
            0 => ChildLinkType::None,
            1 => ChildLinkType::Link,
            2 => ChildLinkType::EmbeddedContainer,
            3 => ChildLinkType::PathCompressed,
            _ => panic!("Use of undefined link type"),
        }
    }
}

/// The bitfield representing a top node header.
#[bitfield(u8)]
pub struct SubNode {
    /// See [`NodeType`]
    #[bits(2)]
    pub type_flag: NodeType,

    /// The header type of this node, see [`NodeState`]
    #[bits(1)]
    pub container_type: NodeState,

    /// The stored delta encoding if this node. If `delta == 0`, the next 8 bits are the stored key. If `delta != 0`, the key is calculated
    /// in respect to the predecessor key. In that case, the node does not store the key explicitly.
    #[bits(3)]
    pub delta: u8,

    /// Stores information about which child link type is used.
    #[bits(2)]
    pub child_container: ChildLinkType,
}

impl SubNode {
    /// Returns, if this node is delta encoded.
    pub fn has_delta(&self) -> bool {
        self.delta() != 0
    }

    /// Returns, if this node is a top node.
    pub fn is_top_node(&self) -> bool {
        self.container_type() == NodeState::TopNode
    }

    /// Returns, if this node is a sub node.
    pub fn is_sub_node(&self) -> bool {
        self.container_type() == NodeState::SubNode
    }
}

#[cfg(test)]
mod test_sub_node {
    use crate::hyperion::components::node::{NodeState, NodeType};
    use crate::hyperion::components::sub_node::{ChildLinkType, SubNode};

    #[test]
    fn test_sub_node_retrieval() {
        let sub_node: SubNode = SubNode::new()
            .with_type_flag(NodeType::InnerNode)
            .with_container_type(NodeState::TopNode)
            .with_delta(0b110)
            .with_child_container(ChildLinkType::EmbeddedContainer);

        assert_eq!(size_of_val(&sub_node), 1);
        assert_eq!(sub_node.type_flag(), NodeType::InnerNode);
        assert_eq!(sub_node.container_type(), NodeState::TopNode);
        assert_eq!(sub_node.delta(), 0b110);
        assert_eq!(sub_node.child_container(), ChildLinkType::EmbeddedContainer);
    }
}
