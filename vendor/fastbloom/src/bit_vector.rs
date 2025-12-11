use std::ops::Range;

/// The number of bits in the bit mask that is used to index a u64's bits.
///
/// u64's are used to store 64 bits, so the index ranges from 0 to 63.
const BIT_MASK_LEN: u32 = u32::ilog2(u64::BITS);

/// Gets 6 last bits from the bit index, which are used to index a u64's bits.
const BIT_MASK: u64 = (1 << BIT_MASK_LEN) - 1;

/// A bit vector partitioned in to blocks.
///
/// Blocks are a power of 2 length array of u64's.
/// The bit size of blocks therefore can be 64, 128, 256, etc.
/// Only `BlockedBitVec`'s with block sizes following this rule can be constructed.
///
/// Loading a block, such as with `get_block`, is cache efficient.
/// Membership checks can be done locally inside a block.
///
/// Indexing a block is also efficient, since it can be done with bit operators because
/// the size of a block is a power of 2.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BlockedBitVec<const BLOCK_SIZE_BITS: usize> {
    bits: Vec<u64>,
}

impl<const BLOCK_SIZE_BITS: usize> BlockedBitVec<BLOCK_SIZE_BITS> {
    /// Block size in u64s
    const BLOCK_SIZE: usize = BLOCK_SIZE_BITS / 64;
    /// Used to shift u64 index
    const LOG2_BLOCK_SIZE: u32 = u32::ilog2(Self::BLOCK_SIZE as u32);

    #[inline]
    const fn block_range(index: usize) -> Range<usize> {
        let block_index = index * Self::BLOCK_SIZE;
        block_index..(block_index + Self::BLOCK_SIZE)
    }

    /// The number of blocks in the `BlockedBitVector`
    #[inline]
    pub fn num_blocks(&self) -> usize {
        self.bits.len() >> Self::LOG2_BLOCK_SIZE
    }

    /// Returns a reference to the raw data for the `i`th block in the `BlockedBitVec`
    #[inline]
    pub fn get_block(&self, i: usize) -> &[u64] {
        &self.bits[Self::block_range(i)]
    }

    /// Returns a mutable reference to the raw data for the `i`th block in the `BlockedBitVec`
    #[inline]
    pub fn get_block_mut(&mut self, index: usize) -> &mut [u64] {
        &mut self.bits[Self::block_range(index)]
    }

    /// Returns a bit "coordinate" (u64 and bit index pair) from a index in a block, `bit_index`.
    /// The `usize` is used to get the corresponding u64 from `self.bits`,
    /// the u64 is a mask used to get the corresponding bit from that u64.
    #[inline]
    const fn coordinate(bit_index: usize) -> (usize, u64) {
        let index = bit_index.wrapping_shr(BIT_MASK_LEN);
        let bit = 1u64 << (bit_index as u64 & BIT_MASK);
        (index, bit)
    }

    /// Sets the `bit_index`th bit in the block to 1.
    #[inline]
    pub fn set_for_block(block: &mut [u64], bit_index: usize) -> bool {
        let (index, bit) = Self::coordinate(bit_index);
        let previously_contained = block[index] & bit > 0;
        block[index] |= bit;
        previously_contained
    }

    /// Returns true if the `bit_index`th in the block is 1.
    #[inline]
    pub fn check_for_block(block: &[u64], bit_index: usize) -> bool {
        let (index, bit) = Self::coordinate(bit_index);
        block[index] & bit > 0
    }

    #[inline]
    pub fn as_slice(&self) -> &[u64] {
        &self.bits
    }

    #[inline]
    pub fn clear(&mut self) {
        for i in 0..self.bits.len() {
            self.bits[i] = 0;
        }
    }
}

impl<const BLOCK_SIZE_BITS: usize> From<Vec<u64>> for BlockedBitVec<BLOCK_SIZE_BITS> {
    fn from(mut bits: Vec<u64>) -> Self {
        let num_u64s_per_block = BLOCK_SIZE_BITS / 64;
        let r = bits.len() % num_u64s_per_block;
        if r != 0 {
            bits.extend(vec![0; num_u64s_per_block - r]);
        }
        bits.shrink_to_fit();
        Self { bits }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use std::collections::HashSet;

    #[test]
    fn test_to_from_vec() {
        fn to_from_<const N: usize>(size: usize) {
            let b: BlockedBitVec<N> = vec![0u64; size].into();
            assert_eq!(b.num_blocks() * N, b.as_slice().len() * 64);
            assert!(size <= b.as_slice().len());
            assert!((size + N) > b.as_slice().len());
        }
        for size in 1..=10009 {
            to_from_::<64>(size);
            to_from_::<128>(size);
            to_from_::<256>(size);
            to_from_::<512>(size);
        }
    }

    #[test]
    fn test_only_random_inserts_are_contained() {
        let mut vec = BlockedBitVec::<64>::from(vec![0; 80]);
        let mut control = HashSet::new();
        let mut rng = rand::rng();

        for _ in 0..100000 {
            let block_index = rng.random_range(0..vec.num_blocks());
            let bit_index = rng.random_range(0..64);

            let block = vec.get_block(block_index);

            if !control.contains(&(block_index, bit_index)) {
                assert!(!BlockedBitVec::<64>::check_for_block(block, bit_index));
            }
            let block_mut = vec.get_block_mut(block_index);
            control.insert((block_index, bit_index));
            BlockedBitVec::<64>::set_for_block(block_mut, bit_index);
            assert!(BlockedBitVec::<64>::check_for_block(block_mut, bit_index));
        }
    }
}
