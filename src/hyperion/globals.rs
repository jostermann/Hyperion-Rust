/*#[cfg(test)]
mod hyperion_components_test {
    use crate::hyperion::components::container::{Container, EmbeddedContainer};
    use crate::hyperion::components::nodes::{
        Node, NodeHeader, PathCompressedNodeHeader, SubNode, SnodeJumptableEntry, TopNode,
    };

    const TYPE_FLAG: u8 = 0b01;
    const T_CONTAINER_FLAG: u8 = 0b0;
    const S_CONTAINER_FLAG: u8 = 0b1;
    const DELTA: u8 = 0b110;
    const JUMP_SUCCESSOR: u8 = 0b1;
    const JUMP_TABLE: u8 = 0b1;
    const CHILD_CONTAINER_TYPE: u8 = 0b11;

    const TNODE: TopNode = TopNode::new()
        .with_type_flag(TYPE_FLAG)
        .with_container_type(T_CONTAINER_FLAG)
        .with_delta(DELTA)
        .with_jump_successor(JUMP_SUCCESSOR)
        .with_jump_table(JUMP_TABLE);

    const SNODE: SubNode = SubNode::new()
        .with_type_flag(TYPE_FLAG)
        .with_container_type(S_CONTAINER_FLAG)
        .with_delta(DELTA)
        .with_child_container(CHILD_CONTAINER_TYPE);

    #[test]
    fn test_tnode() {
        assert_eq!(size_of_val(&TNODE), 1);
        assert_eq!(TNODE.type_flag(), TYPE_FLAG);
        assert_eq!(TNODE.container_type(), T_CONTAINER_FLAG);
        assert_eq!(TNODE.delta(), DELTA);
        assert_eq!(TNODE.jump_successor(), JUMP_SUCCESSOR);
        assert_eq!(TNODE.jump_table(), JUMP_TABLE);
    }

    #[test]
    fn test_snode_header() {
        assert_eq!(size_of_val(&SNODE), 1);
        assert_eq!(SNODE.type_flag(), TYPE_FLAG);
        assert_eq!(SNODE.container_type(), S_CONTAINER_FLAG);
        assert_eq!(SNODE.delta(), DELTA);
        assert_eq!(SNODE.child_container(), CHILD_CONTAINER_TYPE);
    }

    #[test]
    fn test_compressed_header() {
        let size: u8 = 0b0101101;
        let value_present: u8 = 0b1;
        let pc_node: PathCompressedNodeHeader = PathCompressedNodeHeader::new()
            .with_size(size)
            .with_value_present(value_present);
        assert_eq!(size_of_val(&pc_node), 1);
        assert_eq!(pc_node.size(), size);
        assert_eq!(pc_node.value_present(), value_present);
    }

    #[test]
    fn test_container_header() {
        let size: u32 = 0b1001001011100010110;
        let free_bytes: u32 = 0b00010101;
        let jump_table: u32 = 0b101;
        let split_delay: u32 = 0b01;
        let container: Container = Container::new()
            .with_size(size)
            .with_free_bytes(free_bytes)
            .with_jump_table(jump_table)
            .with_split_delay(split_delay);
        assert_eq!(size_of_val(&container), 4);
        assert_eq!(container.size(), size);
        assert_eq!(container.free_bytes(), free_bytes);
        assert_eq!(container.jump_table(), jump_table);
        assert_eq!(container.split_delay(), split_delay);
    }

    #[test]
    fn test_embedded_container_header() {
        let size: u8 = 0b10010101;
        let emb_container: EmbeddedContainer = EmbeddedContainer::new().with_size(size);
        assert_eq!(size_of_val(&emb_container), 1);
        assert_eq!(emb_container.size(), size);
    }

    #[test]
    fn test_snode_jumptable_entry() {
        let offset: u32 = 0b100110100101100011000011;
        let key: u32 = 0b00011011;
        let snode_jumptable_entry: SnodeJumptableEntry =
            SnodeJumptableEntry::new().with_offset(offset).with_key(key);
        assert_eq!(size_of_val(&snode_jumptable_entry), 4);
        assert_eq!(snode_jumptable_entry.offset(), offset);
        assert_eq!(snode_jumptable_entry.key(), key);
    }

    #[test]
    fn test_node_size() {
        let header: NodeHeader = NodeHeader { top_node: TNODE };
        unsafe {
            assert_eq!(size_of_val(&header.top_node), 1);
        }

        let stored_value: u8 = 116;
        assert_eq!(size_of_val(&stored_value), 1);

        let node: Node = Node {
            header,
            stored_value,
        };
        assert_eq!(size_of_val(&node), 2);
        assert_eq!(size_of_val(&node.header), 1);
        assert_eq!(size_of_val(&node.stored_value), 1);
    }
}
*/
