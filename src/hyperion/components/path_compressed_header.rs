use bitfield_struct::bitfield;

#[bitfield(u8)]
pub struct PathCompressedNodeHeader {
    #[bits(1)]
    pub value_present: bool,

    #[bits(7)]
    pub size: usize,
}

impl PathCompressedNodeHeader {
    pub fn as_raw(&self) -> *const PathCompressedNodeHeader {
        self as *const PathCompressedNodeHeader
    }

    pub fn as_raw_char(&self) -> *const u8 {
        self.as_raw() as *const u8
    }
}

#[cfg(test)]
mod test_path_compressed_node {
    use crate::hyperion::components::path_compressed_header::PathCompressedNodeHeader;

    #[test]
    fn test_compressed_header() {
        let size: usize = 0b0101101;
        let pc_node: PathCompressedNodeHeader = PathCompressedNodeHeader::new().with_size(size).with_value_present(true);

        assert_eq!(size_of_val(&pc_node), 1);
        assert_eq!(pc_node.size(), size);
        assert!(pc_node.value_present());
    }
}
