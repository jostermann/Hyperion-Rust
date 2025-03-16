use bitfield_struct::bitfield;

#[bitfield(u8)]
pub struct PathCompressedNodeHeader {
    #[bits(1)]
    pub value_present: bool,

    #[bits(7)]
    pub size: u8,
}

impl PathCompressedNodeHeader {
    pub fn as_raw(&self) -> *const PathCompressedNodeHeader {
        self as *const PathCompressedNodeHeader
    }

    pub fn as_raw_char(&self) -> *const u8 {
        self.as_raw() as *const u8
    }
}