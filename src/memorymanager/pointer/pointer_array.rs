//! This module provides a wrapper structure containing a pointer to a
//! variable length array of Metabins.
//!
//! Each superbin has a storage capacity of up to 2^14 metabins, with the
//! actual amount of metabins stored per superbin being variable and subject
//! to continuous change during execution. To maintain compact headers in the
//! superbin, pointers to variable-length arrays of pointers to metabins are stored
//! in the header. This enables metabins to be initialized and deleted individually
//! without altering the size of the superbin.
//!
//! To provide a safe implementation, `PointerArray` wraps the double-pointer
//! construct into `Box`, `Option` and Slices.

use crate::memorymanager::components::metabin::{Metabin, META_MAXMETABINS};
use crate::memorymanager::internals::simd_common::{all_bits_set_256, apply_simd};

/// Defines the wrapper structure and a type alias for the more complex implementation details.
#[derive(Clone)]
pub(crate) struct PointerArray {
    /// Array stores a `Box` pointer to a variable length `slice`, which stores
    /// optional `Box` pointers to Metabins.
    ///
    /// To avoid the use of `NULL`, each entry in the slice is defined as `Some(Metabin)`
    /// or `None`, where `None` marks the slice index as free. The use of
    /// `Box` pointers is beneficial because they provide integrated memory
    /// safety at compile time and the concurrent usage of at most one thread
    /// at a time is guaranteed.
    pub array: Box<[Option<Box<Metabin>>]>,
}

/// Amount of which the `PointerArray` will be enlarged if a reallocation is triggered.
pub(crate) const POINTER_ARRAY_INCREMENT: usize = 16;

impl PointerArray {
    /// Creates a new `PointerArray` with `initial_num_metabin` already initialized.
    ///
    /// Returns the `PointerArray`.
    pub(crate) fn new(initial_num_metabins: usize) -> Self {
        let mut vec: Vec<Option<Box<Metabin>>> = Vec::with_capacity(POINTER_ARRAY_INCREMENT);
        vec.extend((0..initial_num_metabins).map(|_| Some(Box::new(Metabin::default()))));
        vec.extend((initial_num_metabins..POINTER_ARRAY_INCREMENT).map(|_| None));
        Self {
            array: vec.into_boxed_slice(),
        }
    }

    /// Initializes a new metabin at the given index.
    ///
    /// Returns `true`, if the operation was successful.
    /// Return `false`, otherwise.
    pub(crate) fn new_metabin_at(&mut self, index: usize) -> bool {
        (index < POINTER_ARRAY_INCREMENT).then(|| self.array[index] = Some(Box::new(Metabin::default()))).is_some()
    }

    // pub(crate) fn set(&mut self, index: usize, metabin: Metabin) -> bool {
    // (index < POINTER_ARRAY_INCREMENT)
    // .then(|| self.array[index] = Some(Box::new(metabin)))
    // .is_some()
    // }

    /// Returns an immutable reference to the metabin stored at the given index.
    ///
    /// Returns `&Some(metabin)` if a metabin is present.
    /// Returns `None`, if no metabin is stored at that index or if the index
    /// is out of bounds.
    pub(crate) fn get(&self, index: usize) -> Option<&Metabin> {
        self.array.get(index)?.as_ref().map(|b| b.as_ref())
    }

    /// Returns a mutable reference to the metabin stored at the given index.
    ///
    /// Returns `&mut Some(metabin)` if a metabin is present.
    /// Returns `None`, if no metabin is stored at that index or if the index
    /// is out of bounds.
    pub(crate) fn get_mut(&mut self, index: usize) -> Option<&mut Metabin> {
        self.array.get_mut(index)?.as_mut().map(|b: &mut Box<Metabin>| b.as_mut())
    }

    /// Deletes the metabin at the given index.
    ///
    /// Returns `true`, if the deletion was successful.
    /// Returns `false`, otherwise.
    ///
    /// # Safety
    /// _This function does not check if the underlying bins still have reserved
    /// chunks. Calling this function without tearing the bins down will result
    /// in memory leakage._
    pub(crate) fn delete_metabin(&mut self, index: usize) -> bool {
        if index >= POINTER_ARRAY_INCREMENT {
            return false;
        }

        if let Some(metabin) = &self.array[index] {
            let is_full = apply_simd(&metabin.bin_usage_mask, all_bits_set_256);

            if is_full {
                self.array[index] = None;
                return true;
            }
        }
        false
    }

    /// Checks if the `PointerArray` is full and must be extended. Performs an
    /// extension of the capacity automatically.
    ///
    /// Returns `true` if the extension was successful.
    /// Returns `false`, otherwise.
    pub(crate) fn check_extend_pointer_array(&mut self, current_initialized_metabins: usize) -> bool {
        if current_initialized_metabins % POINTER_ARRAY_INCREMENT == 0 {
            self.realloc_pointer_array()
        } else {
            true
        }
    }

    /// Extends the capacity by POINTER_ARRAY_INCREMENT
    ///
    /// Returns `true` if the extension was successful.
    /// Returns `false`, otherwise.
    fn realloc_pointer_array(&mut self) -> bool {
        let mut vec = self.array.to_vec();

        if vec.len() + POINTER_ARRAY_INCREMENT > META_MAXMETABINS as usize {
            return false;
        }

        // reserve additional POINTER_ARRAY_INCREMENT indices
        vec.reserve(POINTER_ARRAY_INCREMENT);
        vec.extend((0..POINTER_ARRAY_INCREMENT).map(|_| Some(Box::new(Metabin::default()))));
        self.array = vec.into_boxed_slice();
        true
    }
}
