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
