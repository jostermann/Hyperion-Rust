use bitfield_struct::bitfield;
use std::intrinsics::copy_nonoverlapping;

const ENCODING_MAP_PERFOPT: [u8; 256] = [
    70, 86, 102, 118, 134, 150, 166, 182, 198, 245, 6, 38, 54, 22, 214, 230, 246, 7, 23, 39, 55, 71, 87, 103, 119, 135, 151, 167, 183, 199, 215, 231,
    229, 227, 243, 4, 20, 36, 52, 68, 84, 100, 116, 132, 148, 164, 180, 196, 67, 83, 99, 115, 131, 147, 163, 179, 195, 211, 212, 228, 244, 5, 21, 37,
    53, 209, 210, 82, 50, 161, 146, 178, 34, 241, 35, 242, 66, 130, 225, 193, 194, 19, 2, 18, 177, 114, 226, 98, 3, 162, 51, 69, 85, 101, 117, 133,
    149, 48, 49, 176, 144, 0, 240, 17, 128, 80, 129, 81, 160, 224, 64, 32, 33, 113, 96, 112, 16, 208, 65, 192, 97, 1, 145, 165, 181, 197, 213, 247,
    8, 24, 40, 56, 72, 88, 104, 120, 136, 152, 168, 184, 200, 216, 232, 248, 9, 25, 41, 57, 73, 89, 105, 121, 137, 153, 169, 185, 201, 217, 233, 249,
    10, 26, 42, 58, 74, 90, 106, 122, 138, 154, 170, 186, 202, 218, 234, 250, 11, 27, 43, 59, 75, 91, 107, 123, 139, 155, 171, 187, 203, 219, 235,
    251, 12, 28, 44, 60, 76, 92, 108, 124, 140, 156, 172, 188, 204, 220, 236, 252, 13, 29, 45, 61, 77, 93, 109, 125, 141, 157, 173, 189, 205, 221,
    237, 253, 14, 30, 46, 62, 78, 94, 110, 126, 142, 158, 174, 190, 206, 222, 238, 254, 15, 31, 47, 63, 79, 95, 111, 127, 143, 159, 175, 191, 207,
    223, 239, 255,
];

const ENCODING_MAP_MEMORYOPT: [u8; 256] = [
    100, 101, 102, 103, 104, 105, 106, 107, 108, 95, 96, 98, 99, 97, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124,
    125, 126, 94, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 77, 78, 79, 80, 81, 82, 83, 29,
    45, 37, 35, 26, 41, 43, 34, 31, 50, 47, 36, 40, 30, 28, 44, 49, 32, 33, 27, 39, 46, 38, 48, 42, 51, 84, 85, 86, 87, 88, 89, 3, 19, 11, 9, 0, 15,
    17, 8, 5, 24, 21, 10, 14, 4, 2, 18, 23, 6, 7, 1, 13, 20, 12, 22, 16, 25, 90, 91, 92, 93, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137,
    138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166,
    167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195,
    196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224,
    225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253,
    254, 255,
];

#[derive(Debug, PartialOrd, PartialEq)]
pub enum Preprocessor {
    None = 0,
    UniformKeyDistributionSingleThread = 1,
    UniformKeyDistributionMultiThread = 2,
    EnglishLanguageDataMemory = 3,
    EnglishLanguageDataPerformance = 4,
}

impl Preprocessor {
    /// Transforms its states into a 2 bit representation.
    pub(crate) const fn into_bits(self) -> u8 {
        self as _
    }

    /// Transforms its states from an 8 bit value into a named state.
    ///
    /// # Panics
    /// Panics if an invalid processor type was found.
    pub(crate) const fn from_bits(value: u8) -> Self {
        match value {
            0 => Preprocessor::None,
            1 => Preprocessor::UniformKeyDistributionSingleThread,
            2 => Preprocessor::UniformKeyDistributionMultiThread,
            3 => Preprocessor::EnglishLanguageDataMemory,
            4 => Preprocessor::EnglishLanguageDataPerformance,
            _ => panic!("Use of undefined node type"),
        }
    }
}

pub type PreprocessCallbackInterface = fn(*const u8, &mut u16, *mut u8);

#[bitfield(u32)]
struct TransformUniformMTKeyBitmap {
    #[bits(6)]
    pub a: u32,
    #[bits(4)]
    pub b: u32,
    #[bits(8)]
    pub c: u32,
    #[bits(6)]
    pub d: u32,
    #[bits(8)]
    __: u32,
}

#[bitfield(u32)]
struct TransformUniformSTKeyBitmap {
    #[bits(6)]
    pub a: u32,
    #[bits(6)]
    pub b: u32,
    #[bits(6)]
    pub c: u32,
    #[bits(6)]
    pub d: u32,
    #[bits(8)]
    __: u32,
}

pub fn preprocess_english_language_memory(key: *const u8, key_len: &mut u16, destination: *mut u8) {
    let mut src = key;
    let mut dest = destination;
    for _ in 0..*key_len {
        unsafe {
            *dest = ENCODING_MAP_MEMORYOPT[*src as usize];
            dest = dest.add(1);
            src = src.add(1);
        }
    }
}

pub fn preprocess_english_language_performance(key: *const u8, key_len: &mut u16, destination: *mut u8) {
    let mut src = key;
    let mut dest = destination;
    for _ in 0..*key_len {
        unsafe {
            *dest = ENCODING_MAP_PERFOPT[*src as usize];
            dest = dest.add(1);
            src = src.add(1);
        }
    }
}

pub fn preprocess_uniform_keys_mt(key: *const u8, key_len: &mut u16, destination: *mut u8) {
    unsafe {
        let mut dest = destination;
        *dest = *key;
        dest = dest.add(1);
        let pattern = key.add(1) as *mut TransformUniformMTKeyBitmap;
        *dest = ((*pattern).a() << 2) as u8;
        dest = dest.add(1);
        *dest = ((*pattern).b() << 4) as u8;
        dest = dest.add(1);
        *dest = (*pattern).c() as u8;
        dest = dest.add(1);
        *dest = ((*pattern).d() << 2) as u8;
        dest = dest.add(1);
        copy_nonoverlapping(key.add(4), dest, *key_len as usize - 4);
        *key_len += 1;
    }
}

pub fn preprocess_uniform_keys_st(key: *const u8, key_len: &mut u16, destination: *mut u8) {
    unsafe {
        let mut dest = destination;
        *dest = *key;
        dest = dest.add(1);
        let pattern = key.add(1) as *mut TransformUniformSTKeyBitmap;
        *dest = ((*pattern).a() << 2) as u8;
        dest = dest.add(1);
        *dest = ((*pattern).b() << 2) as u8;
        dest = dest.add(1);
        *dest = ((*pattern).c() << 2) as u8;
        dest = dest.add(1);
        *dest = ((*pattern).d() << 2) as u8;
        dest = dest.add(1);
        copy_nonoverlapping(key.add(4), dest, *key_len as usize - 4);
        *key_len += 1;
    }
}
