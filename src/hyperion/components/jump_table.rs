use bitfield_struct::bitfield;

pub const SUBLEVEL_JUMPTABLE_ENTRIES: usize = 15;
pub const SUBLEVEL_JUMPTABLE_SHIFTBITS: usize = 4;
pub const TOPLEVEL_JUMPTABLE_ENTRIES: usize = 7;

#[derive(Copy, Clone)]
pub struct TopNodeJumpTable {
    pub jump: [u16; SUBLEVEL_JUMPTABLE_ENTRIES]
}

#[bitfield(u32, order = Msb)]
pub struct SubNodeJumpTableEntry {
    #[bits(24)]
    pub offset: u32,

    #[bits(8)]
    pub key: u8
}

#[derive(Copy, Clone)]
#[repr(packed)]
pub struct SubNodeJumpTable {
    pub jump: [SubNodeJumpTableEntry; TOPLEVEL_JUMPTABLE_ENTRIES]
}
