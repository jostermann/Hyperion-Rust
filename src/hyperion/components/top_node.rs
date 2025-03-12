use bitfield_struct::bitfield;

use crate::hyperion::components::node::NodeType;

#[bitfield(u8)]
pub struct TopNode {
    #[bits(2)]
    pub type_flag: NodeType,

    #[bits(1)]
    pub container_type: u8,

    #[bits(3)]
    pub delta: u8,

    #[bits(1)]
    pub jump_table_present: bool,

    #[bits(1)]
    pub jump_successor_present: bool,
}

impl TopNode {
    pub fn has_delta(&self) -> bool {
        self.delta() != 0
    }

    pub fn is_top_node(&self) -> bool {
        self.container_type() == 0
    }

    pub fn is_sub_node(&self) -> bool {
        self.container_type() == 1
    }
}
