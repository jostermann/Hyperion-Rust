use bitfield_struct::bitfield;

/// The amount of stored jump table entries in a top node.
pub const TOP_NODE_JUMP_TABLE_ENTRIES: usize = 15;
/// The amount of shift bits to retrieve an entry from the top node jump table for some key `i`.
pub const TOP_NODE_JUMP_TABLE_SHIFT: usize = 4;
/// The amount of stored container jump table entries in the container jump table:
pub const CONTAINER_JUMP_TABLE_ENTRIES: usize = 7;
/// TODO
pub const TOPLEVEL_NODE_JUMP_HWM: usize = 9;

/// Raw jump table of a top node.
///
/// Top node jump tables are stored behind its corresponding top node and allow to jump directly to any stored sub node. Since the information
/// about predecessor keys is lost when jumping, only predefined sub nodes can be jumped to.
///
/// An entry at index `i` points to the sub nodes storing the partial key `16 * (i + 1)`.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct TopNodeJumpTable {
    /// The 15 entries long array pointing to 15 sub nodes.
    pub jump: [u16; TOP_NODE_JUMP_TABLE_ENTRIES],
}

/// A single entry of the `ContainerJumpTable`.
///
/// This entry stores jump information for the referenced top node. The `offset` field describes the offset of the referenced top node from the
/// container base address. The key field stores the key of the referenced top node. This allows to scan for a specific key or range of keys and
/// to jump directly to them.
#[bitfield(u32)]
pub struct ContainerJumpTableEntry {
    /// The offset of the referenced top node from the containers base address.
    #[bits(24)]
    pub offset: usize,

    /// The key of the references top node.
    #[bits(8)]
    pub key: u8,
}

/// Raw jump table referenced to by some container.
///
/// Container jump tables allow to directly jump to any top node stored in this jump table. All entries are stored in ascending order in respect
/// to the entries keys.
///
/// One single `ContainerJumpTable` stores up to 7 `ContainerJumpTableEntries`. A `Container` can reference to up to 7
/// `ContainerJumpTables` via it's jump table flag.
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct ContainerJumpTable {
    pub jump: [ContainerJumpTableEntry; CONTAINER_JUMP_TABLE_ENTRIES],
}
