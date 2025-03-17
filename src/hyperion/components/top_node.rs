use bitfield_struct::bitfield;

use crate::hyperion::components::node::{NodeState, NodeType};

/// The bitfield representing a top node header.
#[bitfield(u8)]
pub struct TopNode {
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

    /// Flag, whether this node has a [`TopNodeJumpTable`] present.
    #[bits(1)]
    pub jump_table_present: bool,

    /// Flag, whether this node as a jump successor present. If this field is set, the node is followed by a 16 bit jump offset to the nodes
    /// sibling [`TopNode`].
    #[bits(1)]
    pub jump_successor_present: bool,
}

impl TopNode {
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
mod test_top_node {
    use crate::hyperion::components::node::{NodeState, NodeType};
    use crate::hyperion::components::top_node::TopNode;

    #[test]
    fn test_top_node_retrieval() {
        let top_node: TopNode = TopNode::new()
            .with_type_flag(NodeType::InnerNode)
            .with_container_type(NodeState::TopNode)
            .with_delta(0b110)
            .with_jump_table_present(false)
            .with_jump_successor_present(false);

        assert_eq!(size_of_val(&top_node), 1);
        assert_eq!(top_node.type_flag(), NodeType::InnerNode);
        assert_eq!(top_node.container_type(), NodeState::TopNode);
        assert_eq!(top_node.delta(), 0b110);
        assert!(!top_node.jump_successor_present());
        assert!(!top_node.jump_table_present());
    }
}
