use crate::hyperion::components::container::{
    shift_container, update_space, wrap_shift_container, Container, EmbeddedContainer, RootContainerEntryInner, CONTAINER_MAX_EMBEDDED_DEPTH,
    DEFAULT_CONTAINER_SIZE,
};
use crate::hyperion::components::context::TraversalType::{
    EmptyOneCharTopNode, EmptyTwoCharTopNode, EmptyTwoCharTopNodeInFirstCharScope, FilledOneCharTopNode, FilledTwoCharTopNode,
    FilledTwoCharTopNodeInFirstCharScope,
};
use crate::hyperion::components::context::{
    ContainerInjectionContext, ContainerTraversalContext, EmbeddedTraversalContext, JumpContext, JumpTableSubContext, OperationCommand,
    PathCompressedEjectionContext, DELTA_MAX_VALUE, MAX_CONTAINER_JUMP_TABLES, TOPLEVEL_AGGRESSIVE_GROWTH__HWM, TOP_NODE_JUMP_TABLE_HWM,
};
use crate::hyperion::components::jump_table::{ContainerJumpTable, CONTAINER_JUMP_TABLE_ENTRIES, TOPLEVEL_NODE_JUMP_HWM};
use crate::hyperion::components::node::NodeType::{Invalid, LeafNodeWithValue};
use crate::hyperion::components::node::{get_sub_node_key, get_top_node_key, Node, NodeState, NodeValue};
use crate::hyperion::components::node_header::{
    as_sub_node, as_top_node, as_top_node_mut, compare_path_compressed_node, create_child_container, create_node, create_path_compressed_context,
    create_top_node_jump_table, get_child_container_pointer, get_destination_from_top_node_jump_table, get_jump_successor_value, get_offset,
    get_offset_jump_successor, get_offset_node_value, get_offset_sub_node, get_offset_top_node, get_successor, register_jump_context, set_node_value,
    update_path_compressed_node, NodeCreationOptions, NodeHeader,
};
use crate::hyperion::components::operation_context::JumpStates::{JumpPoint1, JumpPoint2, NoJump};
use crate::hyperion::components::return_codes::ReturnCode;
use crate::hyperion::components::return_codes::ReturnCode::{UnknownOperation, OK};
use crate::hyperion::components::sub_node::ChildLinkType;
use crate::hyperion::components::sub_node::ChildLinkType::PathCompressed;
use crate::hyperion::components::top_node::TopNode;
use crate::hyperion::internals::atomic_pointer::AtomicEmbContainer;
use crate::hyperion::internals::core::{log_to_file, GLOBAL_CONFIG};
use crate::hyperion::internals::errors::{
    ERR_EMPTY_EMB_STACK, ERR_NO_ARENA, ERR_NO_CAST_MUT_REF, ERR_NO_INPUT_VALUE, ERR_NO_KEY, ERR_NO_NEXT_CONTAINER, ERR_NO_NODE, ERR_NO_RETURN_VALUE,
    ERR_NO_SUCCESSOR, ERR_NO_VALUE,
};
use crate::memorymanager::api::{get_pointer, reallocate, Arena, HyperionPointer};
use bitfield_struct::bitfield;
use std::cmp::Ordering;
use std::intrinsics::write_bytes;
use std::ptr::{null_mut, read_unaligned, write_unaligned};

/// Stores, if the next container stored by next_container_pointer is valid.
#[derive(Debug, PartialEq)]
pub enum ContainerValidTypes {
    /// The next container is invalid. Setting this option will end all operations.
    Invalid = 0,
    /// Setting this option will enable all operations on the [`Container`] type.
    ContainerValid = 1,
    /// Setting this option will enable all operations on the [`EmbeddedContainer`] type.
    EmbeddedContainerValid = 2,
}

impl ContainerValidTypes {
    /// Transforms its states into a 2 bit representation.
    pub(crate) const fn into_bits(self) -> u8 {
        self as _
    }

    /// Transforms its states from an 8 bit value into a named state.
    ///
    /// # Panics
    /// Panics if an invalid container valid type was found.
    pub(crate) const fn from_bits(value: u8) -> Self {
        match value {
            0 => ContainerValidTypes::Invalid,
            1 => ContainerValidTypes::ContainerValid,
            2 => ContainerValidTypes::EmbeddedContainerValid,
            _ => panic!("Use of undefined container valid type"),
        }
    }
}

#[derive(PartialEq)]
pub enum JumpStates {
    JumpPoint1,
    JumpPoint2,
    NoJump,
}

/// Stores metadata used for controlling the amount of loops performed on the trie.
#[bitfield(u8)]
pub struct OperationContextHeader {
    /// Stores the operation to perform in this iteration.
    #[bits(2)]
    pub command: OperationCommand,
    /// Stores the validity state of the next found container.
    #[bits(2)]
    pub next_container_valid: ContainerValidTypes,
    /// Stores if the operation is done.
    #[bits(1)]
    pub operation_done: bool,
    /// Stores if the put operation was successful.
    #[bits(1)]
    pub performed_put: bool,
    /// Stores if the child container is path compressed.
    #[bits(1)]
    pub pathcompressed_child: bool,
    #[bits(1)]
    __: u8,
}

#[derive(Default)]
#[repr(C)]
pub struct OperationContext {
    pub header: OperationContextHeader,
    pub chained_pointer_hook: u8,
    pub key_len_left: i32,
    pub key: Option<*mut u8>,
    pub jump_context: JumpContext,
    pub root_container_entry: Option<*mut RootContainerEntryInner>,
    pub embedded_traversal_context: EmbeddedTraversalContext,
    pub top_jump_table_context: JumpTableSubContext,
    pub next_container_pointer: Option<*mut HyperionPointer>,
    pub arena: Option<*mut Arena>,
    pub path_compressed_ejection_context: Option<PathCompressedEjectionContext>,
    pub return_value: Option<*mut NodeValue>,
    pub input_value: Option<*mut NodeValue>,
    pub container_injection_context: ContainerInjectionContext,
}

impl OperationContext {
    /// Returns a mutable reference to the current root container.
    ///
    /// # Panics
    /// - if the root container pointer stored in [`OperationContext`] is a null pointer.
    #[inline]
    pub fn get_root_container(&mut self) -> &mut Container {
        unsafe { self.embedded_traversal_context.root_container.as_mut().expect(ERR_NO_CAST_MUT_REF) }
    }

    /// Returns a pointer to the current root container.
    #[inline]
    pub fn get_root_container_pointer(&mut self) -> *mut Container {
        self.embedded_traversal_context.root_container
    }

    /// Returns a mutable reference to the current arena.
    ///
    /// # Panics
    /// - if the arena pointer stored in [`OperationContext`] is a null pointer.
    pub fn get_arena(&mut self) -> &mut Arena {
        unsafe { self.arena.expect(ERR_NO_ARENA).as_mut().expect(ERR_NO_CAST_MUT_REF) }
    }

    /// Returns a mutable reference to the current root container's [`HyperionPointer`].
    ///
    /// # Panics
    /// - if the root container pointer stored in [`OperationContext`] is a null pointer.
    pub fn get_root_container_hyp_pointer(&mut self) -> &mut HyperionPointer {
        unsafe { self.embedded_traversal_context.root_container_pointer.as_mut().expect(ERR_NO_CAST_MUT_REF) }
    }

    /// Returns a mutable reference to the next [`EmbeddedContainer`].
    ///
    /// # Panics
    /// - if the next embedded pointer stored in [`OperationContext`] is a null pointer.
    /// - if no next embedded pointer is stored.
    pub fn get_next_embedded_container(&mut self) -> &mut EmbeddedContainer {
        unsafe { self.embedded_traversal_context.next_embedded_container.expect(ERR_NO_NEXT_CONTAINER).as_mut().expect(ERR_NO_CAST_MUT_REF) }
    }

    /// Returns a pointer to the next [`EmbeddedContainer`].
    pub fn get_next_embedded_container_pointer(&mut self) -> *mut EmbeddedContainer {
        self.get_next_embedded_container() as *mut EmbeddedContainer
    }

    /// Returns a mutable reference to the next embedded container's offset.
    pub fn get_next_embedded_container_offset(&mut self) -> &mut i32 {
        &mut self.embedded_traversal_context.next_embedded_container_offset
    }

    /// Returns a mutable reference to the stored [`PathCompressedEjectionContext`].
    /// # Panics
    /// - if no [`PathCompressedEjectionContext`] is stored.
    pub fn get_pc_ejection_context(&mut self) -> &mut PathCompressedEjectionContext {
        self.path_compressed_ejection_context.as_mut().expect(ERR_NO_VALUE)
    }

    /// Returns a mutable reference to the stored [`ContainerInjectionContext`].
    pub fn get_injection_context(&mut self) -> &mut ContainerInjectionContext {
        &mut self.container_injection_context
    }

    /// Returns the root container pointer stored in the [`ContainerInjectionContext`].
    /// # Panics
    /// - if no root container is stored in the [`ContainerInjectionContext`].
    pub fn get_injection_root_container_pointer(&mut self) -> *mut Container {
        self.container_injection_context.root_container.expect(ERR_NO_VALUE)
    }

    /// Returns a mutable reference to the root container stored in [`ContainerInjectionContext`].
    /// # Panics
    /// - if the root container stored in [`ContainerInjectionContext`] is a null pointer.
    pub fn get_injection_root_container(&mut self) -> &mut Container {
        unsafe { self.get_injection_root_container_pointer().as_mut().expect(ERR_NO_CAST_MUT_REF) }
    }

    /// Resets the current [`JumpContext`], without removing it from the [`OperationContext`].
    pub fn flush_jump_context(&mut self) {
        self.jump_context.flush()
    }

    /// Resets the current [`JumpTableSubContext`], without removing it from the [`OperationContext`].
    pub fn flush_jump_table_sub_context(&mut self) {
        self.top_jump_table_context.flush()
    }

    /// Returns a mutable reference to the stored return value.
    /// # Panics
    /// - if no return value is stored.
    /// - if the return value pointer is a null pointer.
    pub fn get_return_value_mut(&mut self) -> &mut NodeValue {
        unsafe { self.return_value.expect(ERR_NO_RETURN_VALUE).as_mut().expect(ERR_NO_CAST_MUT_REF) }
    }

    /// Returns a mutable reference to the stored input value.
    /// # Panics
    /// - if no input value is stored.
    /// - if the input value pointer is a null pointer.
    pub fn get_input_value_mut(&mut self) -> &mut NodeValue {
        unsafe { self.input_value.expect(ERR_NO_INPUT_VALUE).as_mut().expect(ERR_NO_CAST_MUT_REF) }
    }

    /// Returns a mutable reference to the stored [`JumpContext`].
    pub fn get_jump_context_mut(&mut self) -> &mut JumpContext {
        &mut self.jump_context
    }

    /// Returns a mutable reference to the stored key.
    /// # Panics
    /// - if no key is stored.
    /// - if the key pointer stored is a null pointer.
    pub fn get_key_as_mut(&mut self) -> &mut u8 {
        unsafe { self.key.expect(ERR_NO_KEY).as_mut().expect(ERR_NO_CAST_MUT_REF) }
    }
}

/// Checks and expands the container by the `required` amount of bytes.
///
/// This function checks, if an expansion by `required` bytes will overflow the container's current size. If the expansion will _not_ overflow the
/// container's size, a pointer to the next free position will be returned. If the expansion overflows the container's size, a reallocation is
/// triggered, incrementing the container's size by 32 bytes.
///
/// # Safety
/// This function is intended for use on [`Container`]. Executing this function on an [`EmbeddedContainer`] might result in undefined behavior.
pub fn new_expand(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, required: u32) -> *mut NodeHeader {
    let free_space_left: u32 = ocx.get_root_container().free_bytes() as u32;
    log_to_file(&format!("nex_expand: {} > {}", required, free_space_left));

    // Check if the expansion overflows the container's size
    if required > free_space_left {
        let old_size: u32 = ocx.get_root_container().size();
        let new_size: u32 = ocx.get_root_container().increment_container_size(required - free_space_left);
        ocx.get_root_container().set_free_size_left(0);
        let root_container_ptr = ocx.get_root_container_pointer();

        let mut node_offset = 0;

        // Store the offset to the current predecessor top node, if present.
        if let Some(top_node) = ocx.top_jump_table_context.top_node.as_mut() {
            unsafe {
                node_offset = (*top_node as *mut u8).offset_from(root_container_ptr as *mut u8) as i32;
            }
        }
        log_to_file(&format!("inner: old: {}, new: {}, offset: {}", old_size, new_size, node_offset));

        assert_eq!(ocx.embedded_traversal_context.embedded_container_depth, 0);

        unsafe {
            *ocx.embedded_traversal_context.root_container_pointer = reallocate(
                ocx.arena.expect(ERR_NO_ARENA),
                ocx.embedded_traversal_context.root_container_pointer,
                new_size as usize,
                ocx.chained_pointer_hook,
            );
        }

        ocx.embedded_traversal_context.root_container =
            get_pointer(ocx.arena.expect(ERR_NO_ARENA), ocx.embedded_traversal_context.root_container_pointer, 1, ocx.chained_pointer_hook)
                as *mut Container;

        ocx.get_root_container().set_free_size_left((new_size - old_size) + free_space_left);

        let root_container_ptr = ocx.get_root_container_pointer();

        // Restore the predecessor node.
        if let Some(predecessor) = ocx.jump_context.predecessor.as_mut() {
            unsafe {
                *predecessor = (root_container_ptr as *mut u8).add(ocx.jump_context.top_node_predecessor_offset_absolute as usize) as *mut NodeHeader;
            }
        }

        // Restore the predecessor top node.
        if node_offset > 0 {
            ocx.top_jump_table_context.top_node = unsafe { Some((root_container_ptr as *mut u8).add(node_offset as usize) as *mut NodeHeader) };
        }
    }
    unsafe { (ocx.embedded_traversal_context.root_container as *mut u8).add(ctx.current_container_offset) as *mut NodeHeader }
}

/// Stored the current context state as [`JumpTableSubContext`].
pub fn safe_top_node_jump_context(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) {
    if ocx.top_jump_table_context.top_node.as_mut().is_none() {
        return;
    }

    if as_top_node(ocx.top_jump_table_context.top_node.expect(ERR_NO_NODE)).jump_table_present()
        && ocx.embedded_traversal_context.embedded_container_depth == 0
    {
        ocx.top_jump_table_context.root_container_sub_char_set = true;
        ocx.top_jump_table_context.root_container_sub_char = ctx.second_char;
    }
}

/// Checks and expands the container by the `required` amount of bytes.
///
/// This function checks, if an expansion by `required` bytes will overflow the container's current size. If the expansion will _not_ overflow the
/// container's size, a pointer to the next free position will be returned. If the expansion overflows the container's size, a reallocation is
/// triggered, incrementing the container's size by 32 bytes.
///
/// # Safety
/// This function is intended for use on [`EmbeddedContainer`]. Executing this function on a [`Container`] might result in undefined behavior.
pub fn new_expand_embedded(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, required: u32) -> *mut NodeHeader {
    let free_space_left: u32 = ocx.get_root_container().free_bytes() as u32;
    log_to_file(&format!("new_expand_embedded: {} > {}", required, free_space_left));

    // Check if the expansion overflows the container's size.
    if required > free_space_left {
        let old_size: u32 = ocx.get_root_container().size();
        let new_size: u32 = ocx.get_root_container().increment_container_size(required - free_space_left);
        ocx.get_root_container().set_free_size_left(0);
        let root_container_ptr = ocx.get_root_container_pointer();

        // Force-store the offset from the stored top node in the jump context.
        let node_offset =
            unsafe { (ocx.top_jump_table_context.top_node.expect(ERR_NO_NODE) as *mut u8).offset_from(root_container_ptr as *mut u8) as i32 };
        log_to_file(&format!("inner: old: {}, new: {}, offset: {}", old_size, new_size, node_offset));

        let mut embedded_stack_offsets: [i32; CONTAINER_MAX_EMBEDDED_DEPTH] = [0; CONTAINER_MAX_EMBEDDED_DEPTH];

        // Force-store the offsets of all currently stored embedded containers.
        if let Some(stack) = ocx.embedded_traversal_context.embedded_stack.as_mut() {
            for (i, container) in stack.iter_mut().enumerate().take(ocx.embedded_traversal_context.embedded_container_depth as usize).rev() {
                embedded_stack_offsets[i] =
                    unsafe { container.as_mut().expect(ERR_NO_NEXT_CONTAINER).get_as_mut_memory().offset_from(root_container_ptr as *mut u8) as i32 };
            }
        } else {
            panic!("{}", ERR_EMPTY_EMB_STACK);
        }

        unsafe {
            *ocx.embedded_traversal_context.root_container_pointer =
                reallocate(ocx.get_arena(), ocx.get_root_container_hyp_pointer(), new_size as usize, ocx.chained_pointer_hook);
        }

        ocx.embedded_traversal_context.root_container =
            get_pointer(ocx.get_arena(), ocx.get_root_container_hyp_pointer(), 1, ocx.chained_pointer_hook) as *mut Container;

        unsafe {
            let p_new: *mut u8 = (ocx.get_root_container_pointer() as *mut u8).add(old_size as usize);
            write_bytes(p_new, 0, (new_size - old_size) as usize);
            ocx.embedded_traversal_context.next_embedded_container = Some(
                (ocx.embedded_traversal_context.root_container as *mut u8).add(ocx.embedded_traversal_context.next_embedded_container_offset as usize)
                    as *mut EmbeddedContainer,
            );
        }

        ocx.get_root_container().set_free_size_left((new_size - old_size) + free_space_left);
        let root_container_ptr = ocx.embedded_traversal_context.root_container;

        // Restore the offset of all embedded containers.
        if let Some(stack) = ocx.embedded_traversal_context.embedded_stack.as_mut() {
            for (i, container) in stack.iter_mut().enumerate().take(ocx.embedded_traversal_context.embedded_container_depth as usize).rev() {
                *container = Some(AtomicEmbContainer::new_from_pointer(unsafe {
                    (root_container_ptr as *mut u8).add(embedded_stack_offsets[i] as usize) as *mut EmbeddedContainer
                }));
            }
        } else {
            panic!("{}", ERR_EMPTY_EMB_STACK);
        }

        // Restore the predecessor node.
        if let Some(predecessor) = ocx.jump_context.predecessor.as_mut() {
            unsafe {
                *predecessor = (root_container_ptr as *mut u8).add(ocx.jump_context.top_node_predecessor_offset_absolute as usize) as *mut NodeHeader;
            }
        }

        // Restore the top node of the jump table context.
        if node_offset > 0 {
            unsafe {
                ocx.top_jump_table_context.top_node = Some((root_container_ptr as *mut u8).add(node_offset as usize) as *mut NodeHeader);
            }
        }
    }

    unsafe {
        (ocx.embedded_traversal_context.root_container as *mut u8)
            .add(ctx.current_container_offset + ocx.embedded_traversal_context.next_embedded_container_offset as usize) as *mut NodeHeader
    }
}

/// Inserts a jump successor to the top node stored in the [`JumpContext`].
///
/// This function inserts a jump successor to the node encoded by the jump value. A jump from the top node to the sibling top node can then be done
/// by using the jump value as offset.
pub fn insert_jump_successor(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, jump_value: u16) -> *mut NodeHeader {
    log_to_file(&format!("insert_jump jump_value: {}", jump_value));
    new_expand(ocx, ctx, size_of::<NodeValue>() as u32);

    let node_head: *mut NodeHeader = unsafe {
        (ocx.get_root_container_pointer() as *mut u8).add(ocx.jump_context.top_node_predecessor_offset_absolute as usize) as *mut NodeHeader
    };

    assert!(ocx.jump_context.top_node_predecessor_offset_absolute > 0);
    assert_eq!(as_top_node(node_head).container_type(), NodeState::TopNode);

    let free_size_left: usize = ocx.get_root_container().free_bytes() as usize;
    let node_offset_to_jump: usize = get_offset_jump_successor(node_head);
    let shift_amount = ocx.get_root_container().size() as usize
        - (free_size_left + node_offset_to_jump + ocx.jump_context.top_node_predecessor_offset_absolute as usize);

    unsafe {
        // Shift the containers memory to fit a 16-bit jump successor behind the current node
        shift_container((node_head as *mut u8).add(node_offset_to_jump), size_of::<u16>(), shift_amount);

        as_top_node_mut(node_head).set_jump_successor_present(true);
        let target = (node_head as *mut u8).add(get_offset_jump_successor(node_head)) as *mut u16;
        let current_value = read_unaligned(target);
        log_to_file(&format!("before jump_insert: {}", current_value));

        // Write the jump successor value to the current node
        write_unaligned(target, current_value + jump_value);
        log_to_file(&format!("after jump_insert: {}", read_unaligned(target)));
        update_space(size_of::<u16>() as i16, ocx, ctx);
        ctx.current_container_offset += size_of::<u16>();
        (ocx.get_root_container_pointer() as *mut u8).add(ctx.current_container_offset) as *mut NodeHeader
    }
}

pub fn meta_expand(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, required: u32) -> *mut NodeHeader {
    if ocx.embedded_traversal_context.embedded_container_depth == 0 {
        return new_expand(ocx, ctx, required);
    }
    new_expand_embedded(ocx, ctx, required)
}

/// Scans through the embedded container and inserts both first_char and second_char.
pub fn scan_put_embedded(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) -> ReturnCode {
    ctx.header.set_node_type(1);

    loop {
        let mut node_header: *mut NodeHeader = unsafe {
            (ocx.embedded_traversal_context.next_embedded_container.expect(ERR_NO_NEXT_CONTAINER) as *mut u8).add(ctx.current_container_offset)
                as *mut NodeHeader
        };

        if ctx.current_container_offset
            >= unsafe { (*(ocx.embedded_traversal_context.next_embedded_container.expect(ERR_NO_NEXT_CONTAINER))).size() as usize }
        {
            ctx.header.set_node_type(0);
        }

        match ctx.as_combined_header() {
            EmptyOneCharTopNode => {
                // Found an empty top node. Insert the key directly at the found position.
                let key_delta_top = ctx.key_delta_top();
                create_node(
                    node_header,
                    ocx,
                    ctx,
                    NodeCreationOptions {
                        container_depth: NodeState::TopNode,
                        set_key: key_delta_top == 0,
                        add_value: true,
                        key_delta: key_delta_top,
                        embedded: true,
                    },
                );
                return OK;
            },
            FilledOneCharTopNode => {
                // Found a top node already storing one key
                if as_top_node(node_header).container_type() == NodeState::TopNode {
                    let key = get_top_node_key(node_header as *mut Node, ctx);

                    match key.cmp(&ctx.first_char) {
                        Ordering::Less => {
                            // Due to the ascending key order, cannot insert the key here
                            ctx.header.set_last_top_char_set(true);
                            ctx.last_top_char_seen = key;
                        },
                        Ordering::Equal => {
                            // Store the key directly at this position
                            return handle_expand(ocx, ctx, node_header, true);
                        },
                        Ordering::Greater => {
                            // Insert the key in front of the found top node.
                            ctx.header.set_force_shift_before_insert(true);
                            ctx.header.set_in_first_char_scope(true);
                            let key_delta_top = ctx.key_delta_top();
                            create_node(
                                node_header,
                                ocx,
                                ctx,
                                NodeCreationOptions {
                                    container_depth: NodeState::TopNode,
                                    set_key: key_delta_top == 0,
                                    add_value: true,
                                    key_delta: key_delta_top,
                                    embedded: true,
                                },
                            );
                            return OK;
                        },
                    }
                    // Get the next top node
                    ctx.current_container_offset += get_offset_top_node(node_header);
                    log_to_file(&format!("scan_put_embedded (top) set current container offset to {}", ctx.current_container_offset));
                    continue;
                }
                // Jump over the next sub node
                ctx.current_container_offset += get_offset_sub_node(node_header);
                log_to_file(&format!("scan_put_embedded (sub) set current container offset to {}", ctx.current_container_offset));
                continue;
            },
            EmptyTwoCharTopNode => {
                let key_delta_top = ctx.key_delta_top();
                node_header = create_node(
                    node_header,
                    ocx,
                    ctx,
                    NodeCreationOptions {
                        container_depth: NodeState::TopNode,
                        set_key: key_delta_top == 0,
                        add_value: false,
                        key_delta: key_delta_top,
                        embedded: true,
                    },
                );
                ctx.header.set_in_first_char_scope(true);
                ctx.current_container_offset += get_offset_top_node(node_header);
                log_to_file(&format!("scan_put_embedded set current container offset to {}", ctx.current_container_offset));
            },
            FilledTwoCharTopNode => {
                if as_top_node(node_header).container_type() == NodeState::TopNode {
                    let key = get_top_node_key(node_header as *mut Node, ctx);

                    match key.cmp(&ctx.first_char) {
                        Ordering::Less => {
                            ctx.header.set_last_top_char_set(true);
                            ctx.last_top_char_seen = key;
                        },
                        Ordering::Equal => {
                            ctx.header.set_in_first_char_scope(true);
                        },
                        Ordering::Greater => {
                            ctx.header.set_force_shift_before_insert(true);
                            ctx.header.set_in_first_char_scope(true);
                            let key_delta_top = ctx.key_delta_top();
                            node_header = create_node(
                                node_header,
                                ocx,
                                ctx,
                                NodeCreationOptions {
                                    container_depth: NodeState::TopNode,
                                    set_key: key_delta_top == 0,
                                    add_value: false,
                                    key_delta: key_delta_top,
                                    embedded: true,
                                },
                            );
                        },
                    }
                    ctx.current_container_offset += get_offset_top_node(node_header);
                    log_to_file(&format!("scan_put_embedded (top) set current container offset to {}", ctx.current_container_offset));
                    continue;
                }
                ctx.current_container_offset += get_offset_sub_node(node_header);
                log_to_file(&format!("scan_put_embedded (sub) set current container offset to {}", ctx.current_container_offset));
                continue;
            },
            EmptyTwoCharTopNodeInFirstCharScope => {
                let key_delta_sub = ctx.key_delta_sub();
                create_node(
                    node_header,
                    ocx,
                    ctx,
                    NodeCreationOptions {
                        container_depth: NodeState::SubNode,
                        set_key: key_delta_sub == 0,
                        add_value: ctx.header.end_operation(),
                        key_delta: key_delta_sub,
                        embedded: true,
                    },
                );
                return OK;
            },
            FilledTwoCharTopNodeInFirstCharScope => {
                if as_top_node(node_header).container_type() == NodeState::SubNode {
                    let key = get_sub_node_key(node_header as *mut Node, ctx, false);

                    match key.cmp(&ctx.second_char) {
                        Ordering::Less => {
                            ctx.header.set_last_sub_char_set(true);
                            ctx.last_sub_char_seen = key;
                            ctx.current_container_offset += get_offset_sub_node(node_header);
                            log_to_file(&format!("scan_put_embedded set current container offset to {}", ctx.current_container_offset));
                            continue;
                        },
                        Ordering::Equal => {
                            return handle_equal_keys(ocx, ctx, node_header);
                        },
                        Ordering::Greater => {
                            ctx.header.set_force_shift_before_insert(true);
                            let key_delta_sub = ctx.key_delta_sub();
                            create_node(
                                node_header,
                                ocx,
                                ctx,
                                NodeCreationOptions {
                                    container_depth: NodeState::SubNode,
                                    set_key: key_delta_sub == 0,
                                    add_value: ctx.header.end_operation(),
                                    key_delta: key_delta_sub,
                                    embedded: true,
                                },
                            );
                            return OK;
                        },
                    }
                } else {
                    ctx.header.set_force_shift_before_insert(true);
                    let key_delta_sub = ctx.key_delta_sub();
                    create_node(
                        node_header,
                        ocx,
                        ctx,
                        NodeCreationOptions {
                            container_depth: NodeState::SubNode,
                            set_key: key_delta_sub == 0,
                            add_value: ctx.header.end_operation(),
                            key_delta: key_delta_sub,
                            embedded: true,
                        },
                    );
                    return OK;
                }
            },
            _ => {
                return UnknownOperation;
            },
        }
    }
}

pub fn scan_put_single(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) -> ReturnCode {
    let mut node_head: *mut NodeHeader = null_mut();
    let mut key = 0;
    let mut jump_point = NoJump;

    ctx.max_offset = (ocx.get_root_container().size() as i32 - ocx.get_root_container().free_bytes() as i32) as usize;

    initialize_data_for_scan(ocx, ctx, node_head, &mut key, &mut jump_point);

    loop {
        match jump_point {
            NoJump => {
                node_head = unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ctx.current_container_offset) as *mut NodeHeader };

                if ctx.max_offset > ctx.current_container_offset {
                    jump_point = JumpPoint1;
                    continue;
                }

                if ctx.current_container_offset >= ocx.get_root_container().size() as usize || as_top_node(node_head).type_flag() == Invalid {
                    ocx.jump_context.top_node_key = ctx.first_char as i32;
                    let key_delta_top = ctx.key_delta_top();
                    create_node(
                        node_head,
                        ocx,
                        ctx,
                        NodeCreationOptions {
                            container_depth: NodeState::TopNode,
                            set_key: key_delta_top == 0,
                            add_value: true,
                            key_delta: key_delta_top,
                            embedded: false,
                        },
                    );
                    return OK;
                }
                jump_point = JumpPoint1;
                continue;
            },
            JumpPoint1 => {
                jump_point = NoJump;
                if as_top_node(node_head).container_type() == NodeState::TopNode {
                    key = get_top_node_key(node_head as *mut Node, ctx);
                    jump_point = JumpPoint2;
                    continue;
                }
                ocx.jump_context.sub_nodes_seen += 1;
                ctx.current_container_offset += get_offset_sub_node(node_head);
            },
            JumpPoint2 => {
                ocx.jump_context.top_node_key = key as i32;

                match key.cmp(&ctx.first_char) {
                    Ordering::Less => {
                        ctx.header.set_last_top_char_set(true);
                        ctx.last_top_char_seen = key;
                    },
                    Ordering::Equal => {
                        register_jump_context(node_head, ctx, ocx);
                        return handle_expand(ocx, ctx, node_head, false);
                    },
                    Ordering::Greater => {
                        ocx.jump_context.predecessor = None;
                        ctx.header.set_force_shift_before_insert(true);
                        let key_delta_top = ctx.key_delta_top();
                        create_node(
                            node_head,
                            ocx,
                            ctx,
                            NodeCreationOptions {
                                container_depth: NodeState::TopNode,
                                set_key: key_delta_top == 0,
                                add_value: true,
                                key_delta: key_delta_top,
                                embedded: false,
                            },
                        );
                        return OK;
                    },
                }

                if as_top_node(node_head).jump_successor_present() {
                    ctx.current_container_offset = get_jump_successor_value(node_head);
                } else {
                    ctx.current_container_offset += get_offset_top_node(node_head);
                }
                ocx.jump_context.predecessor = Some(node_head);
                ocx.jump_context.top_node_predecessor_offset_absolute =
                    unsafe { (node_head as *mut u8).offset_from(ocx.get_root_container_pointer() as *mut u8) as i32 };
                ocx.jump_context.sub_nodes_seen = 0;
                jump_point = NoJump;
                continue;
            },
        }
    }
}

#[allow(unused_assignments)]
pub fn initialize_data_for_scan(
    ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, mut node_head: *mut NodeHeader, key: &mut u8, jump_point: &mut JumpStates,
) {
    if ocx.get_root_container().jump_table() == 0 {
        ctx.current_container_offset = ocx.get_root_container().get_container_head_size();
    } else {
        *key = ocx.get_root_container().get_key_and_offset_with_jump_table(ctx.first_char, &mut ctx.current_container_offset);
        node_head = unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ctx.current_container_offset) as *mut NodeHeader };

        if *key != 0 {
            *jump_point = JumpPoint2;
        }
    }
}

/// Expands the current container by one [`NodeValue`] and stores the current input value as the node's stored value.
fn handle_expand(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, mut node_head: *mut NodeHeader, embedded: bool) -> ReturnCode {
    if as_top_node(node_head).type_flag() != LeafNodeWithValue && ocx.input_value.is_some() {
        // The node is not a leaf node with value. Therefore, no node value field is reserved in the container's memory. To store a node value
        // the container's memory must be shifted,
        node_head = if embedded {
            new_expand_embedded(ocx, ctx, size_of::<NodeValue>() as u32)
        } else {
            new_expand(ocx, ctx, size_of::<NodeValue>() as u32)
        };

        unsafe {
            // Shift the container's memory to fit another node value
            wrap_shift_container(
                ocx.get_root_container_pointer(),
                (node_head as *mut u8).add(get_offset_node_value(node_head)),
                size_of::<NodeValue>(),
            );
        }
        update_space(size_of::<NodeValue>() as i16, ocx, ctx);
    }
    // Set the node's value from the input value
    set_node_value(node_head, ocx);
    OK
}

/// Scans through the container and inserts the second_char key.
pub fn scan_put_phase2(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) -> ReturnCode {
    let mut jump_point = NoJump;

    ctx.max_offset = (ocx.get_root_container().size() as i32 - ocx.get_root_container().free_bytes() as i32) as usize;
    log_to_file(&format!("scan_put_phase2 set safe offset to {}", ctx.max_offset));

    let mut node_head = unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ctx.current_container_offset) as *mut NodeHeader };

    loop {
        match jump_point {
            NoJump => {
                assert!(ctx.max_offset > 0);

                if ctx.max_offset > ctx.current_container_offset {
                    jump_point = JumpPoint1;
                    continue;
                }

                if ctx.current_container_offset >= ocx.get_root_container().size() as usize || as_top_node(node_head).type_flag() == Invalid {
                    // Reached the end of either the container or the stored data. Insert a new sub node at the previously found valid position.
                    ctx.header.set_node_type(0);
                    let key_delta_sub = ctx.key_delta_sub();
                    create_node(
                        node_head,
                        ocx,
                        ctx,
                        NodeCreationOptions {
                            container_depth: NodeState::SubNode,
                            set_key: key_delta_sub == 0,
                            add_value: ctx.header.end_operation(),
                            key_delta: key_delta_sub,
                            embedded: false,
                        },
                    );
                    return OK;
                }

                jump_point = JumpPoint1;
                continue;
            },
            JumpPoint1 => {
                jump_point = NoJump;
                if as_top_node(node_head).container_type() == NodeState::SubNode {
                    let key = get_sub_node_key(node_head as *mut Node, ctx, false);
                    log_to_file(&format!("scan_put_phase2 found key {}", key));

                    // Compare the second_char key with the found sub node key
                    match key.cmp(&ctx.second_char) {
                        Ordering::Less => {
                            // Since the search key is smaller than the found key, and the keys are stored in ascending order, the key cannot
                            // be inserted here.
                            ctx.current_container_offset += get_offset_sub_node(node_head);
                            node_head = unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ctx.current_container_offset) as *mut NodeHeader };
                            ctx.header.set_last_sub_char_set(true);
                            ctx.last_sub_char_seen = key;
                            ocx.jump_context.sub_nodes_seen += 1;

                            if ocx.jump_context.sub_nodes_seen >= TOP_NODE_JUMP_TABLE_HWM as i32 {
                                // The distance between the top node and the to be inserted sub node is too large. Create a jump table and restart
                                // the scan.
                                create_top_node_jump_table(ocx.top_jump_table_context.top_node.expect(ERR_NO_NODE), ocx, ctx);
                                ctx.flush();
                                ocx.flush_jump_context();
                                ocx.flush_jump_table_sub_context();
                                ctx.current_container_offset = ocx.get_root_container().get_container_head_size();
                                //log_to_file(&format!("scan_put_phase2 set current container offset to {}", ctx.current_container_offset));
                                return scan_put(ocx, ctx);
                            }
                        },
                        Ordering::Equal => {
                            // Both keys are equal. Use handle_equal_keys to check on how to insert the new key.
                            return handle_equal_keys(ocx, ctx, node_head);
                        },
                        Ordering::Greater => {
                            // The new key can be inserted in front of the found sub node's key. Force shift the sub node forward and insert the
                            // new key.
                            ctx.header.set_force_shift_before_insert(true);
                            if ctx.header.last_sub_char_set() && (ctx.second_char - ctx.last_sub_char_seen) <= DELTA_MAX_VALUE {
                                create_node(
                                    node_head,
                                    ocx,
                                    ctx,
                                    NodeCreationOptions {
                                        container_depth: NodeState::SubNode,
                                        set_key: false,
                                        add_value: ctx.header.end_operation(),
                                        key_delta: ctx.second_char - ctx.last_sub_char_seen,
                                        embedded: false,
                                    },
                                );
                            } else {
                                if !ctx.header.last_sub_char_set() {
                                    ctx.header.set_last_sub_char_set(true);
                                    ctx.last_sub_char_seen = 0;
                                }
                                create_node(
                                    node_head,
                                    ocx,
                                    ctx,
                                    NodeCreationOptions {
                                        container_depth: NodeState::SubNode,
                                        set_key: true,
                                        add_value: ctx.header.end_operation(),
                                        key_delta: 0,
                                        embedded: false,
                                    },
                                );
                            }
                            return OK;
                        },
                    }
                } else {
                    // Found a top node. Insert the key directly as sub node.
                    ctx.header.set_force_shift_before_insert(true);
                    let key_delta_sub = ctx.key_delta_sub();
                    create_node(
                        node_head,
                        ocx,
                        ctx,
                        NodeCreationOptions {
                            container_depth: NodeState::SubNode,
                            set_key: key_delta_sub == 0,
                            add_value: ctx.header.end_operation(),
                            key_delta: key_delta_sub,
                            embedded: false,
                        },
                    );
                    return OK;
                }
            },
            _ => {
                break;
            },
        }
    }
    OK
}

pub fn scan_put_phase2_withjt(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, destination: u8) -> ReturnCode {
    log_to_file("scan_put_phase2_withjt");
    let mut key = destination;
    let mut jump_point = NoJump;

    ctx.max_offset = (ocx.get_root_container().size() as i32 - ocx.get_root_container().free_bytes() as i32) as usize;

    let mut node_head = unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ctx.current_container_offset) as *mut NodeHeader };

    if key != 0 {
        jump_point = JumpPoint2;
    }

    loop {
        match jump_point {
            NoJump => {
                if ctx.max_offset > ctx.current_container_offset {
                    jump_point = JumpPoint1;
                    continue;
                }

                if ctx.current_container_offset >= ocx.get_root_container().size() as usize || as_top_node(node_head).type_flag() == Invalid {
                    ctx.header.set_node_type(0);
                    let key_delta_sub = ctx.key_delta_sub();
                    create_node(
                        node_head,
                        ocx,
                        ctx,
                        NodeCreationOptions {
                            container_depth: NodeState::SubNode,
                            set_key: key_delta_sub == 0,
                            add_value: ctx.header.end_operation(),
                            key_delta: key_delta_sub,
                            embedded: false,
                        },
                    );
                    return OK;
                }
                jump_point = JumpPoint1;
                continue;
            },
            JumpPoint1 => {
                if as_top_node(node_head).container_type() == NodeState::SubNode {
                    key = get_sub_node_key(node_head as *mut Node, ctx, false);
                    jump_point = JumpPoint2;
                    continue;
                } else {
                    ctx.header.set_force_shift_before_insert(true);
                    let key_delta_sub = ctx.key_delta_sub();
                    create_node(
                        node_head,
                        ocx,
                        ctx,
                        NodeCreationOptions {
                            container_depth: NodeState::SubNode,
                            set_key: key_delta_sub == 0,
                            add_value: ctx.header.end_operation(),
                            key_delta: key_delta_sub,
                            embedded: false,
                        },
                    );
                    return OK;
                }
            },
            JumpPoint2 => {
                jump_point = NoJump;

                match key.cmp(&ctx.second_char) {
                    Ordering::Less => {
                        ctx.current_container_offset += get_offset_sub_node(node_head);
                        node_head = unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ctx.current_container_offset) as *mut NodeHeader };
                        ctx.header.set_last_sub_char_set(true);
                        ctx.last_sub_char_seen = key;
                    },
                    Ordering::Equal => {
                        return handle_equal_keys(ocx, ctx, node_head);
                    },
                    Ordering::Greater => {
                        ctx.header.set_force_shift_before_insert(true);
                        let key_delta_sub = ctx.key_delta_sub();
                        create_node(
                            node_head,
                            ocx,
                            ctx,
                            NodeCreationOptions {
                                container_depth: NodeState::SubNode,
                                set_key: key_delta_sub == 0,
                                add_value: ctx.header.end_operation(),
                                key_delta: key_delta_sub,
                                embedded: false,
                            },
                        );
                        return OK;
                    },
                }
            },
        }
    }
}

/// Decides on how to insert the keys in the case that an equal sub node key was found.
fn handle_equal_keys(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, node_head: *mut NodeHeader) -> ReturnCode {
    if ctx.header.end_operation() {
        // Force insert the key
        handle_expand(ocx, ctx, node_head, false);
    } else {
        match as_sub_node(node_head).child_container() {
            ChildLinkType::None => {
                create_child_container(node_head, ocx, ctx);
            },
            PathCompressed => {
                if compare_path_compressed_node(node_head, ocx) {
                    update_path_compressed_node(node_head, ocx, ctx);
                } else {
                    create_path_compressed_context(node_head, ocx);
                    create_child_container(node_head, ocx, ctx);
                }
            },
            _ => {
                // The sub node links to either an embedded container or to a separate container.
                // Store the child container pointer in the current operation context and restart the current operation on the child container
                get_child_container_pointer(node_head, ocx, ctx, true);
            },
        }
    }
    OK
}

/// Scans through the container and inserts two nodes for the first_char key and the second_char key.
pub fn scan_put(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) -> ReturnCode {
    let mut node_head: *mut NodeHeader = null_mut();
    let mut toplevel_nodes = TOPLEVEL_NODE_JUMP_HWM as i32;
    let mut jump_point = NoJump;

    // Set the max offset to the last data stored
    ctx.max_offset = (ocx.get_root_container().size() as i32 - ocx.get_root_container().free_bytes() as i32) as usize;
    log_to_file(&format!("scan_put set safe offset to {}", ctx.max_offset));

    if ocx.get_root_container().jump_table() != 0 {
        if (ocx.get_root_container().jump_table() as usize) < MAX_CONTAINER_JUMP_TABLES {
            toplevel_nodes = TOPLEVEL_AGGRESSIVE_GROWTH__HWM as i32;
        }

        // Get the top node's key for the jump table entry that belongs to ctx.first_char
        ocx.jump_context.top_node_key =
            ocx.get_root_container().get_key_and_offset_with_jump_table(ctx.first_char, &mut ctx.current_container_offset) as i32;

        if ocx.jump_context.top_node_key != 0 {
            node_head = unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ctx.current_container_offset) as *mut NodeHeader };
            jump_point = JumpPoint2;
        }
    }

    loop {
        match jump_point {
            NoJump => {
                node_head =
                    unsafe { (ocx.embedded_traversal_context.root_container as *mut u8).add(ctx.current_container_offset) as *mut NodeHeader };

                if ctx.max_offset <= ctx.current_container_offset {
                    // Scanned through all stored nodes and reached the end of the stored data. The reached memory region of this container is
                    // currently all-zeroed and unused.
                    ocx.jump_context.top_node_key = ctx.first_char as i32;
                    let key_delta_top = ctx.key_delta_top();

                    // Create a new top node
                    node_head = create_node(
                        node_head,
                        ocx,
                        ctx,
                        NodeCreationOptions {
                            container_depth: NodeState::TopNode,
                            set_key: key_delta_top == 0,
                            add_value: false,
                            key_delta: key_delta_top,
                            embedded: false,
                        },
                    );
                    ctx.current_container_offset += get_offset_top_node(node_head);
                    log_to_file(&format!("scan_put set current container offset to {}", ctx.current_container_offset));
                    // Create a new sub node
                    create_node(
                        unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ctx.current_container_offset) as *mut NodeHeader },
                        ocx,
                        ctx,
                        NodeCreationOptions {
                            container_depth: NodeState::SubNode,
                            set_key: true,
                            add_value: ctx.header.end_operation(),
                            key_delta: ctx.second_char,
                            embedded: false,
                        },
                    );
                    return OK;
                }

                if as_top_node(node_head).container_type() == NodeState::SubNode {
                    // Need to insert a top node, found a sub node
                    // Rescan for a top node

                    ocx.jump_context.sub_nodes_seen += 1;
                    ctx.current_container_offset += get_offset_sub_node(node_head);
                    log_to_file(&format!("scan_put set current container offset to {}", ctx.current_container_offset));
                    jump_point = NoJump;
                    continue;
                }
                jump_point = JumpPoint1;
                continue;
            },
            JumpPoint1 => {
                if toplevel_nodes == 0 && (ocx.get_root_container().size() as usize) > DEFAULT_CONTAINER_SIZE * 4 {
                    create_container_jump_table(ocx, ctx);
                    ctx.flush();
                    ocx.flush_jump_context();
                    ocx.flush_jump_table_sub_context();
                    return scan_put(ocx, ctx);
                }

                // No jump table present, get the key of the found top node
                ocx.jump_context.top_node_key = get_top_node_key(node_head as *mut Node, ctx) as i32;
                jump_point = JumpPoint2;
                continue;
            },
            JumpPoint2 => {
                toplevel_nodes -= 1;

                // Compare the found top node's key with the key to be inserted
                match ocx.jump_context.top_node_key.cmp(&(ctx.first_char as i32)) {
                    Ordering::Less => {
                        // Since all keys are stored in ascending order in respect to their key, this found branch in the trie has no
                        // space available for the first_char key. This branch will update the search parameters and rescan from the next top node.

                        ctx.header.set_last_top_char_set(true);
                        ctx.last_top_char_seen = ocx.jump_context.top_node_key as u8;

                        let ret = handle_insert_jump(ocx, ctx, node_head);
                        node_head = ret;
                        ocx.jump_context.sub_nodes_seen = 0;

                        if as_top_node(node_head).jump_successor_present() {
                            // The found top node has a jump offset to its sibling top node stored. Update the search parameters and jump directly
                            // to the sibling node.

                            ctx.current_container_offset += get_jump_successor_value(node_head);
                            log_to_file(&format!("scan_put set current container offset to {}", ctx.current_container_offset));
                            ocx.jump_context.predecessor = Some(node_head);
                            ocx.jump_context.top_node_predecessor_offset_absolute =
                                unsafe { (node_head as *mut u8).offset_from(ocx.get_root_container_pointer() as *mut u8) as i32 };
                            node_head = unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ctx.current_container_offset) as *mut NodeHeader };

                            // Since the found top node has a sibling, it is guaranteed that a jump will not result in unused zeroed memory at the
                            // end of this container
                            jump_point = JumpPoint1;
                            continue;
                        }

                        // Get the next top node and rescan in the next trie branch
                        ocx.jump_context.predecessor = Some(node_head);
                        ocx.jump_context.top_node_predecessor_offset_absolute =
                            unsafe { (node_head as *mut u8).offset_from(ocx.get_root_container_pointer() as *mut u8) as i32 };
                        ctx.current_container_offset += get_offset_top_node(node_head);
                        log_to_file(&format!("scan_put set current container offset to {}", ctx.current_container_offset));
                        jump_point = NoJump;
                    },
                    Ordering::Equal => {
                        // Both keys are equal --> the first_char key is already inserted in this container. Start the next scan phase to check
                        // where to insert the second_char key.

                        ctx.header.set_in_first_char_scope(true);
                        let ret = handle_insert_jump(ocx, ctx, node_head);
                        node_head = ret;
                        ocx.top_jump_table_context.top_node = Some(node_head);
                        ocx.jump_context.top_node_predecessor_offset_absolute =
                            unsafe { (node_head as *mut u8).offset_from(ocx.get_root_container_pointer() as *mut u8) as i32 };
                        ocx.jump_context.sub_nodes_seen = 0;
                        ocx.jump_context.predecessor = Some(node_head);

                        if as_top_node(node_head).jump_table_present() {
                            let destination = get_destination_from_top_node_jump_table(node_head, ctx);
                            return scan_put_phase2_withjt(ocx, ctx, destination);
                        }
                        ctx.current_container_offset += get_offset(node_head);
                        log_to_file(&format!("scan_put set current container offset to {}", ctx.current_container_offset));
                        return scan_put_phase2(ocx, ctx);
                    },
                    Ordering::Greater => {
                        // The first_char key can be inserted in front of the found top node. The found top node will be shifted forward in order
                        // to store first_char and second_char in its right position.
                        ctx.header.set_force_shift_before_insert(true);
                        ocx.flush_jump_context();
                        let key_delta_top = ctx.key_delta_top();
                        node_head = create_node(
                            node_head,
                            ocx,
                            ctx,
                            NodeCreationOptions {
                                container_depth: NodeState::TopNode,
                                set_key: key_delta_top == 0,
                                add_value: false,
                                key_delta: key_delta_top,
                                embedded: false,
                            },
                        );
                        ctx.current_container_offset += get_offset_top_node(node_head);
                        log_to_file(&format!("scan_put set current container offset to {}", ctx.current_container_offset));
                        create_node(
                            unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ctx.current_container_offset) as *mut NodeHeader },
                            ocx,
                            ctx,
                            NodeCreationOptions {
                                container_depth: NodeState::SubNode,
                                set_key: true,
                                add_value: ctx.header.end_operation(),
                                key_delta: ctx.second_char,
                                embedded: false,
                            },
                        );
                        return OK;
                    },
                }
            },
        }
    }
}

/// Check if a jump successor can be inserted on the [`TopNode`] stored in the [`JumpContext`]. Inserts the jump, if possible.
///
/// A jump successor is only inserted, if the current node has at least 2 child nodes.
fn handle_insert_jump(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, node_head: *mut NodeHeader) -> *mut NodeHeader {
    if ocx.jump_context.sub_nodes_seen > (GLOBAL_CONFIG.read().top_level_successor_threshold as i32) {
        let jump_value = unsafe {
            ((node_head as *mut u8).offset_from(ocx.get_root_container_pointer() as *mut u8) as u16)
                - ocx.jump_context.top_node_predecessor_offset_absolute as u16
        };
        return insert_jump_successor(ocx, ctx, jump_value);
    }
    node_head
}

/// Inserts a new [`ContainerJumpTable`] to the current [`Container`].
///
/// This function will iterate through all top nodes of the container and register jumps to them. Existing jump tables are rebalanced.
/// If there are too few top nodes to build a new [`ContainerJumpTable`], the function will abort the creation process and leave the container's
/// memory in its previous state.
pub fn create_container_jump_table(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) {
    log_to_file("insert_top_level_jump_table");

    let mut node_cache: Node = Node {
        header: NodeHeader::new_top_node(TopNode::default()),
        key: 0,
    };

    // Each ContainerJumpTableEntry stored a 24-bit offset of the found top node, and an 8-bit key of the found top node.
    let mut found_keys = [0u8; 256];
    let mut found_offsets = [0u32; 256];
    let mut found: usize = 0;
    let mut required_max = 0;

    let mut tmp_ctx = ContainerTraversalContext {
        current_container_offset: ocx.get_root_container().get_container_head_size() + ocx.get_root_container().get_jump_table_size(),
        ..ContainerTraversalContext::default()
    };

    let successor: *mut Node = &mut node_cache;

    let mut node_head = unsafe { (ocx.get_root_container_pointer() as *mut u8).add(tmp_ctx.current_container_offset) as *mut NodeHeader };

    // Iterate through the complete root container
    while (ocx.get_root_container().size() as usize) > tmp_ctx.current_container_offset {
        if as_top_node(node_head).type_flag() == Invalid {
            // Since all unused memory at the end of the root container is zeroed, a node query on this memory yields "invalid" nodes.
            // break loop, since all nodes were scanned
            break;
        }

        // get the current top node's key and store its key and offset for insertion in the jump table entries
        ocx.jump_context.top_node_key = get_top_node_key(node_head as *mut Node, &mut tmp_ctx) as i32;
        found_keys[found] = ocx.jump_context.top_node_key as u8;
        found_offsets[found] = tmp_ctx.current_container_offset as u32;
        tmp_ctx.last_top_char_seen = ocx.jump_context.top_node_key as u8;
        tmp_ctx.header.set_last_top_char_set(true);

        let mut successor_ptr: Option<*mut Node> = Some(successor);
        let skipped = get_successor(node_head, &mut successor_ptr, ocx, &mut tmp_ctx, false);

        if skipped == 0 {
            // Container jump tables store jumps to top nodes only. If skipped is 0, no successor top node exists and all jumps are successfully
            // registered.
            break;
        }

        tmp_ctx.current_container_offset += skipped as usize;
        found += 1;

        // Jump to the found successor top node
        if let Some(successor) = successor_ptr {
            node_head = unsafe { &mut (*successor).header };
        } else {
            panic!("{}", ERR_NO_SUCCESSOR);
        }
    }

    // Containers can reference up to 7 container jump tables. The amount of referenced container jump tables can be dynamic, but each stored
    // jump table must be complete (i.e. must have exactly #CONTAINER_JUMP_TABLE_ENTRIES).
    if found < CONTAINER_JUMP_TABLE_ENTRIES {
        return;
    }

    // Calculate the id of the next container jump table
    let current_jump_table_value = ocx.get_root_container().jump_table();
    let max_increment = MAX_CONTAINER_JUMP_TABLES - current_jump_table_value as usize;
    let mut increment = (found / CONTAINER_JUMP_TABLE_ENTRIES) - current_jump_table_value as usize;

    if (current_jump_table_value < (MAX_CONTAINER_JUMP_TABLES as u8))
        && (found >= (current_jump_table_value as usize * CONTAINER_JUMP_TABLE_ENTRIES + CONTAINER_JUMP_TABLE_ENTRIES))
    {
        // Create a new container jump table
        ocx.flush_jump_context();

        if increment <= 1 {
            increment = 1;
        } else if (increment + current_jump_table_value as usize) > MAX_CONTAINER_JUMP_TABLES {
            increment = max_increment;
        }

        required_max = size_of::<ContainerJumpTable>() * increment;
        let free_size_left = ocx.get_root_container().free_bytes() as i32;
        let container_head_size = ocx.get_root_container().get_container_head_size();
        let bytes_to_move = ocx.get_root_container().size() as i32 - (container_head_size as i32 + free_size_left);

        // If the container is too small to fit another container jump table, increment the container's size
        if (free_size_left as usize) < required_max {
            new_expand(ocx, ctx, required_max as u32);
        }

        // Shift the container's memory starting right after the container's header, to fit another jump table
        unsafe { shift_container((ocx.get_root_container_pointer() as *mut u8).add(container_head_size), required_max, bytes_to_move as usize) };
        ocx.embedded_traversal_context.embedded_container_depth = 0;
        update_space(required_max as i16, ocx, ctx);

        // Update the jump table reference
        ocx.get_root_container().set_jump_table(current_jump_table_value + increment as u8);
    }

    let items = CONTAINER_JUMP_TABLE_ENTRIES * ocx.get_root_container().jump_table() as usize;
    let interval: f32 = (found as f32) / (items as f32);
    assert!(interval < TOPLEVEL_NODE_JUMP_HWM as f32);
    let mut jump_table_entry = ocx.get_root_container().get_jump_table_pointer();

    for i in 0..items {
        let tmp = (interval + interval * i as f32).floor() as usize;
        unsafe {
            // Iterate through all jump table entries and store the previously found top node's offsets and keys
            (*jump_table_entry).set_key(found_keys[tmp]);
            (*jump_table_entry).set_offset(found_offsets[tmp] as usize + required_max);
            jump_table_entry = jump_table_entry.add(1);
        }
    }
}
