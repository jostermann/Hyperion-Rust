use bitfield_struct::bitfield;

use crate::hyperion::components::node::{NodeState, NodeType};

#[derive(Debug, PartialOrd, PartialEq, Eq, Ord)]
pub enum ChildLinkType {
    None = 0,
    Link = 1,
    EmbeddedContainer = 2,
    PathCompressed = 3
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
            _ => panic!("Use of undefined link type")
        }
    }
}

#[bitfield(u8)]
pub struct SubNode {
    #[bits(2)]
    pub type_flag: NodeType,

    #[bits(1)]
    pub container_type: NodeState,

    #[bits(3)]
    pub delta: u8,

    #[bits(2)]
    pub child_container: ChildLinkType
}

impl SubNode {
    pub fn has_delta(&self) -> bool {
        self.delta() != 0
    }

    pub fn is_top_node(&self) -> bool {
        self.container_type() == NodeState::TopNode
    }

    pub fn is_sub_node(&self) -> bool {
        self.container_type() == NodeState::SubNode
    }
}
