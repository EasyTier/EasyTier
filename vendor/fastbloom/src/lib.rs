#![allow(rustdoc::bare_urls)]
#![doc = include_str!("../README.md")]

use std::hash::{BuildHasher, Hash, Hasher};
mod hasher;
pub use hasher::DefaultHasher;
mod builder;
pub use builder::{BuilderWithBits, BuilderWithFalsePositiveRate};
mod bit_vector;
use bit_vector::BlockedBitVec;
mod sparse_hash;
use sparse_hash::SparseHash;
use wide::{u64x2, u64x4};

/// A space efficient approximate membership set data structure.
/// False positives from [`contains`](Self::contains) are possible, but false negatives
/// are not, i.e. [`contains`](Self::contains) for all items in the set is guaranteed to return
/// true, while [`contains`](Self::contains) for all items not in the set probably return false.
///
/// [`BloomFilter`] is supported by an underlying bit vector, chunked into 512, 256, 128, or 64 bit "blocks", to track item membership.
/// To insert, a number of bits are set at positions based on the item's hash in one of the underlying bit vector's block.
/// To check membership, a number of bits are checked at positions based on the item's hash in one of the underlying bit vector's block.
///
/// Once constructed, neither the Bloom filter's underlying memory usage nor number of bits per item change.
///
/// # Examples
/// Basic usage:
/// ```rust
/// use fastbloom::BloomFilter;
///
/// let mut filter = BloomFilter::with_num_bits(1024).expected_items(2);
/// filter.insert("42");
/// filter.insert("🦀");
/// ```
/// Instantiate with a target false positive rate:
/// ```rust
/// use fastbloom::BloomFilter;
///
/// let filter = BloomFilter::with_false_pos(0.001).items(["42", "🦀"]);
/// assert!(filter.contains("42"));
/// assert!(filter.contains("🦀"));
/// ```
/// Use any hasher:
/// ```rust
/// use fastbloom::BloomFilter;
/// use ahash::RandomState;
///
/// let filter = BloomFilter::with_num_bits(1024)
///     .hasher(RandomState::default())
///     .items(["42", "🦀"]);
/// ```
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BloomFilter<const BLOCK_SIZE_BITS: usize = 512, S = DefaultHasher> {
    bits: BlockedBitVec<BLOCK_SIZE_BITS>,
    /// The total target hashes per item that is specified by user or optimized to maximize accuracy
    target_hashes: u64,
    /// The target number of bits to set/check per u64 per item when inserting/checking an item.
    num_rounds: Option<u64>,
    /// The number of hashes per item in addition to `num_rounds`. These hashes can be applied across many `u64`s in a block.
    /// These hashes are in addition to `num_rounds` to make up for rounding errors.
    num_hashes: u64,
    hasher: S,
}

impl BloomFilter {
    fn new_builder<const BLOCK_SIZE_BITS: usize>(
        num_bits: usize,
    ) -> BuilderWithBits<BLOCK_SIZE_BITS> {
        assert!(num_bits > 0);
        // Only available in rust 1.73+
        // let num_u64s = num_bits.div_ceil(64);
        let num_u64s = (num_bits + 64 - 1) / 64;
        BuilderWithBits::<BLOCK_SIZE_BITS> {
            data: vec![0; num_u64s],
            hasher: Default::default(),
        }
    }

    fn new_from_vec<const BLOCK_SIZE_BITS: usize>(
        vec: Vec<u64>,
    ) -> BuilderWithBits<BLOCK_SIZE_BITS> {
        assert!(!vec.is_empty());
        BuilderWithBits::<BLOCK_SIZE_BITS> {
            data: vec,
            hasher: Default::default(),
        }
    }

    fn new_with_false_pos<const BLOCK_SIZE_BITS: usize>(
        fp: f64,
    ) -> BuilderWithFalsePositiveRate<BLOCK_SIZE_BITS> {
        assert!(fp > 0.0);
        BuilderWithFalsePositiveRate::<BLOCK_SIZE_BITS> {
            desired_fp_rate: fp,
            hasher: Default::default(),
        }
    }

    /// Creates a new instance of [`BuilderWithFalsePositiveRate`] to construct a `BloomFilter` with a target false positive rate of `fp`.
    /// The memory size of the underlying bit vector is dependent on the false positive rate and the expected number of items.
    /// # Panics
    /// Panics if the false positive rate, `fp`, is 0.
    ///
    /// # Examples
    /// ```
    /// use fastbloom::BloomFilter;
    /// let bloom = BloomFilter::with_false_pos(0.001).expected_items(1000);
    /// ```
    pub fn with_false_pos(fp: f64) -> BuilderWithFalsePositiveRate<512> {
        BloomFilter::new_with_false_pos::<512>(fp)
    }

    /// Creates a new instance of [`BuilderWithBits`] to construct a `BloomFilter` with `num_bits` number of bits for tracking item membership.
    /// # Panics
    /// Panics if the number of bits, `num_bits`, is 0.
    ///
    /// # Examples
    /// ```
    /// use fastbloom::BloomFilter;
    /// let bloom = BloomFilter::with_num_bits(1024).hashes(4);
    /// ```
    pub fn with_num_bits(num_bits: usize) -> BuilderWithBits<512> {
        BloomFilter::new_builder::<512>(num_bits)
    }

    /// Creates a new instance of [`BuilderWithBits`] to construct a `BloomFilter` initialized with bit vector `bit_vec`.
    ///
    /// To fit the bit block size, `bit_vec` will be padded with `0u64`s and the end.
    ///
    /// # Panics
    /// Panics if the bit vector, `bit_vec`, is empty.
    /// # Examples
    /// ```
    /// use fastbloom::BloomFilter;
    ///
    /// let orig = BloomFilter::with_false_pos(0.001).seed(&42).items([1, 2]);
    /// let num_hashes = orig.num_hashes();
    /// let new = BloomFilter::from_vec(orig.as_slice().to_vec()).seed(&42).hashes(num_hashes);
    ///
    /// assert!(new.contains(&1));
    /// assert!(new.contains(&2));
    /// ```
    pub fn from_vec(bit_vec: Vec<u64>) -> BuilderWithBits<512> {
        BloomFilter::new_from_vec::<512>(bit_vec)
    }
}

const fn validate_block_size(size: usize) -> usize {
    match size {
        64 | 128 | 256 | 512 => size,
        _ => panic!("The only BLOCK_SIZE's allowed are 64, 128, 256, and 512."),
    }
}

impl<const BLOCK_SIZE_BITS: usize, S: BuildHasher> BloomFilter<BLOCK_SIZE_BITS, S> {
    /// Used to grab the last N bits from a hash.
    const BIT_INDEX_MASK: u64 = (validate_block_size(BLOCK_SIZE_BITS) - 1) as u64;

    /// The optimal number of hashes to perform for an item given the expected number of items to be contained in one block.
    /// Proof under "False Positives Analysis": <https://brilliant.org/wiki/bloom-filter/>
    #[inline]
    fn optimal_hashes_f(items_per_block: f64) -> f64 {
        let block_size = BLOCK_SIZE_BITS as f64;

        // `items_per_block` is an average. When block sizes decrease
        // the variance in the actual item per block increase,
        // meaning we are more likely to have a "crowded" block, with
        // way too many bits set. So we decrease the max hashes
        // to decrease this "crowding" effect.
        let min_hashes_mult = (BLOCK_SIZE_BITS as f64) / (512f64);

        let max_hashes = block_size / 64.0f64 * sparse_hash::hashes_for_bits(32) * min_hashes_mult;
        let hashes_per_block = block_size / items_per_block * f64::ln(2.0f64);
        if hashes_per_block > max_hashes {
            max_hashes
        } else if hashes_per_block < 1.0 {
            1.0
        } else {
            hashes_per_block
        }
    }

    #[inline]
    fn bit_index(hash1: &mut u64, hash2: u64) -> usize {
        let h = u64::next_hash(hash1, hash2);
        (h & Self::BIT_INDEX_MASK) as usize
    }

    /// Inserts an element into the Bloom filter.
    ///
    /// # Returns
    ///
    /// `true` if the item may have been previously in the Bloom filter (indicating a potential false positive),
    /// `false` otherwise.
    ///
    /// # Examples
    /// ```
    /// use fastbloom::BloomFilter;
    ///
    /// let mut bloom = BloomFilter::with_num_bits(1024).hashes(4);
    /// bloom.insert(&2);
    /// assert!(bloom.contains(&2));
    /// ```
    #[inline]
    pub fn insert(&mut self, val: &(impl Hash + ?Sized)) -> bool {
        let [mut h1, h2] = get_orginal_hashes(&self.hasher, val);
        let mut previously_contained = true;
        for _ in 0..self.num_hashes {
            // Set bits the traditional way--1 bit per composed hash
            let index = block_index(self.num_blocks(), h1);
            let block = &mut self.bits.get_block_mut(index);
            previously_contained &= BlockedBitVec::<BLOCK_SIZE_BITS>::set_for_block(
                block,
                Self::bit_index(&mut h1, h2),
            );
        }
        if let Some(num_rounds) = self.num_rounds {
            // Set many bits in parallel using a sparse hash
            let index = block_index(self.num_blocks(), h1);
            match BLOCK_SIZE_BITS {
                128 => {
                    let mut hashes_1 = u64x2::h1(&mut h1, h2);
                    let hashes_2 = u64x2::h2(h2);
                    let data = u64x2::sparse_hash(&mut hashes_1, hashes_2, num_rounds);
                    previously_contained &= u64x2::matches(self.bits.get_block(index), data);
                    u64x2::set(self.bits.get_block_mut(index), data);
                }
                256 => {
                    let mut hashes_1 = u64x4::h1(&mut h1, h2);
                    let hashes_2 = u64x4::h2(h2);
                    let data = u64x4::sparse_hash(&mut hashes_1, hashes_2, num_rounds);
                    previously_contained &= u64x4::matches(self.bits.get_block(index), data);
                    u64x4::set(self.bits.get_block_mut(index), data);
                }
                512 => {
                    let hashes_2 = u64x4::h2(h2);
                    let mut hashes_1 = u64x4::h1(&mut h1, h2);
                    for i in 0..2 {
                        let data = u64x4::sparse_hash(&mut hashes_1, hashes_2, num_rounds);
                        previously_contained &=
                            u64x4::matches(&self.bits.get_block(index)[4 * i..], data);
                        u64x4::set(&mut self.bits.get_block_mut(index)[4 * i..], data);
                    }
                }
                _ => {
                    for i in 0..self.bits.get_block(index).len() {
                        let data = u64::sparse_hash(&mut h1, h2, num_rounds);
                        let block = &mut self.bits.get_block_mut(index);
                        previously_contained &= (block[i] & data) == data;
                        block[i] |= data;
                    }
                }
            }
        }
        previously_contained
    }

    /// Checks if an element is possibly in the Bloom filter.
    ///
    /// # Returns
    ///
    /// `true` if the item is possibly in the Bloom filter, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use fastbloom::BloomFilter;
    ///
    /// let bloom = BloomFilter::with_num_bits(1024).items([1, 2, 3]);
    /// assert!(bloom.contains(&1));
    /// ```
    #[inline]
    pub fn contains(&self, val: &(impl Hash + ?Sized)) -> bool {
        let [mut h1, h2] = get_orginal_hashes(&self.hasher, val);
        (0..self.num_hashes).all(|_| {
            // Set bits the traditional way--1 bit per composed hash
            let index = block_index(self.num_blocks(), h1);
            let block = &self.bits.get_block(index);
            BlockedBitVec::<BLOCK_SIZE_BITS>::check_for_block(block, Self::bit_index(&mut h1, h2))
        }) && (if let Some(num_rounds) = self.num_rounds {
            // Set many bits in parallel using a sparse hash
            let index = block_index(self.num_blocks(), h1);
            let block = &self.bits.get_block(index);
            match BLOCK_SIZE_BITS {
                128 => {
                    let mut hashes_1 = u64x2::h1(&mut h1, h2);
                    let hashes_2 = u64x2::h2(h2);
                    let data = u64x2::sparse_hash(&mut hashes_1, hashes_2, num_rounds);
                    u64x2::matches(block, data)
                }
                256 => {
                    let mut hashes_1 = u64x4::h1(&mut h1, h2);
                    let hashes_2 = u64x4::h2(h2);
                    let data = u64x4::sparse_hash(&mut hashes_1, hashes_2, num_rounds);
                    u64x4::matches(block, data)
                }
                512 => {
                    let mut hashes_1 = u64x4::h1(&mut h1, h2);
                    let hashes_2 = u64x4::h2(h2);
                    (0..2).all(|i| {
                        let data = u64x4::sparse_hash(&mut hashes_1, hashes_2, num_rounds);
                        u64x4::matches(&block[4 * i..], data)
                    })
                }
                _ => (0..block.len()).all(|i| {
                    let data = u64::sparse_hash(&mut h1, h2, num_rounds);
                    (block[i] & data) == data
                }),
            }
        } else {
            true
        })
    }

    /// Returns the number of hashes per item.
    #[inline]
    pub fn num_hashes(&self) -> u32 {
        self.target_hashes as u32
    }

    /// Returns the total number of in-memory bits supporting the Bloom filter.
    pub fn num_bits(&self) -> usize {
        self.num_blocks() * BLOCK_SIZE_BITS
    }

    /// Returns the total number of in-memory blocks supporting the Bloom filter.
    /// Each block is `BLOCK_SIZE_BITS` bits.
    pub fn num_blocks(&self) -> usize {
        self.bits.num_blocks()
    }

    /// Returns a `u64` slice of this `BloomFilter`’s contents.
    ///
    /// # Examples
    ///
    /// ```
    /// use fastbloom::BloomFilter;
    ///
    /// let data = vec![0x517cc1b727220a95; 8];
    /// let bloom = BloomFilter::<512>::from_vec(data.clone()).hashes(4);
    /// assert_eq!(bloom.as_slice().to_vec(), data);
    /// ```
    #[inline]
    pub fn as_slice(&self) -> &[u64] {
        self.bits.as_slice()
    }

    /// Clear all of the bits in the Bloom filter, removing all items.
    #[inline]
    pub fn clear(&mut self) {
        self.bits.clear();
    }
}

impl<T, const BLOCK_SIZE_BITS: usize, S: BuildHasher> Extend<T> for BloomFilter<BLOCK_SIZE_BITS, S>
where
    T: Hash,
{
    #[inline]
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        for val in iter {
            self.insert(&val);
        }
    }
}

impl<const BLOCK_SIZE_BITS: usize, S: BuildHasher> PartialEq for BloomFilter<BLOCK_SIZE_BITS, S> {
    fn eq(&self, other: &Self) -> bool {
        self.bits == other.bits
            && self.num_hashes == other.num_hashes
            && self.num_rounds == other.num_rounds
    }
}
impl<const BLOCK_SIZE_BITS: usize, S: BuildHasher> Eq for BloomFilter<BLOCK_SIZE_BITS, S> {}

/// The first two hashes of the value, h1 and h2.
///
/// Subsequent hashes, h, are efficiently derived from these two using `next_hash`.
///
/// This strategy is adapted from <https://www.eecs.harvard.edu/~michaelm/postscripts/rsa2008.pdf>,
/// in which a keyed hash function is used to generate two real hashes, h1 and h2, which are then used to produce
/// many more "fake hahes" h, using h = h1 + i * h2.
///
/// However, here we only use 1 real hash, for performance, and derive h1 and h2:
/// First, we'll think of the 64 bit real hash as two seperate 32 bit hashes, h1 and h2.
///     - Using h = h1 + i * h2 generates entropy in at least the lower 32 bits
/// Second, for more entropy in the upper 32 bits, we'll populate the upper 32 bits for both h1 and h2:
/// For h1, we'll use the original upper bits 32 of the real hash.
///     - h1 is the same as the real hash
/// For h2 we'll use lower 32 bits of h, and multiply by a large constant (same constant as FxHash)
///     - h2 is basically a "weak hash" of h1
#[inline]
pub(crate) fn get_orginal_hashes(
    hasher: &impl BuildHasher,
    val: &(impl Hash + ?Sized),
) -> [u64; 2] {
    let mut state = hasher.build_hasher();
    val.hash(&mut state);
    let h1 = state.finish();
    let h2 = h1.wrapping_shr(32).wrapping_mul(0x51_7c_c1_b7_27_22_0a_95); // 0xffff_ffff_ffff_ffff / 0x517c_c1b7_2722_0a95 = π
    [h1, h2]
}

/// Returns a the block index for an item's hash.
/// The block index must be in the range `0..self.bits.num_blocks()`.
/// This implementation is a more performant alternative to `hash % self.bits.num_blocks()`:
/// <https://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/>
#[inline]
pub(crate) fn block_index(num_blocks: usize, hash: u64) -> usize {
    (((hash >> 32).wrapping_mul(num_blocks as u64)) >> 32) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use std::{collections::HashSet, iter::repeat};

    trait Seeded: BuildHasher {
        fn seeded(seed: &[u8; 16]) -> Self;
    }
    impl Seeded for DefaultHasher {
        fn seeded(seed: &[u8; 16]) -> Self {
            Self::seeded(seed)
        }
    }
    impl Seeded for ahash::RandomState {
        fn seeded(seed: &[u8; 16]) -> Self {
            ahash::RandomState::with_seed(seed[0] as usize)
        }
    }

    fn random_strings(num: usize, min_repeat: u32, max_repeat: u32, seed: u64) -> Vec<String> {
        let mut rng = StdRng::seed_from_u64(seed);
        let gen = rand_regex::Regex::compile(r"[a-zA-Z]+", max_repeat).unwrap();
        (&mut rng)
            .sample_iter(&gen)
            .filter(|s: &String| s.len() >= min_repeat as usize)
            .take(num)
            .collect()
    }

    fn random_numbers(num: usize, seed: u64) -> Vec<u64> {
        let mut rng = StdRng::seed_from_u64(seed);
        repeat(()).take(num).map(|_| rng.random()).collect()
    }

    fn block_counts<const N: usize>(filter: &BloomFilter<N>) -> Vec<u64> {
        (0..filter.num_blocks())
            .map(|i| {
                filter
                    .bits
                    .get_block(i)
                    .iter()
                    .map(|x| x.count_ones() as u64)
                    .sum()
            })
            .collect()
    }

    #[test]
    fn test_to_from_vec() {
        fn to_from_<const N: usize>(size: usize) {
            let vals = random_numbers(100, size as u64);
            let mut b = BloomFilter::new_builder::<N>(size).seed(&1).hashes(3);
            b.extend(vals.clone());
            let x = b.as_slice();
            let b2 = BloomFilter::new_from_vec::<N>(x.to_vec())
                .seed(&1)
                .hashes(3);
            assert_eq!(b, b2);
            assert_eq!(b.num_blocks() * N, b.as_slice().len() * 64);
            assert!(size <= b.as_slice().len() * 64);
            assert!((size + N) > b.as_slice().len() * 64);
        }
        for size in 1..=10009 {
            to_from_::<64>(size);
            to_from_::<128>(size);
            to_from_::<256>(size);
            to_from_::<512>(size);
        }
    }

    #[test]
    fn first_insert_false() {
        let mut filter = BloomFilter::with_num_bits(1202).expected_items(4);
        assert!(!filter.insert(&5));
    }

    #[test]
    fn target_fp_is_accurate() {
        fn target_fp_is_accurate_<const N: usize>(thresh: f64) {
            for mag in 1..=5 {
                let fp = 1.0f64 / 10u64.pow(mag) as f64;
                for num_items_mag in 1..6 {
                    let num_items = 10usize.pow(num_items_mag);
                    let sample_vals = random_numbers(num_items, 42);

                    let filter = BloomFilter::new_with_false_pos::<N>(fp)
                        .seed(&42)
                        .items(sample_vals.iter());
                    let control: HashSet<u64> = sample_vals.clone().into_iter().collect();
                    let anti_vals = random_numbers(100_000, 3);
                    let sample_fp = false_pos_rate_with_vals(&filter, &control, &anti_vals);
                    if sample_fp > 0.0 {
                        let score = sample_fp / fp;
                        // sample_fp can be at most X times greater than requested fp
                        assert!(score <= thresh, "score {score:}, block_size: {N:}, size: {num_items:}, fp: {fp:}, sample fp: {sample_fp:}");
                    }
                }
            }
        }
        target_fp_is_accurate_::<512>(5.0);
        target_fp_is_accurate_::<256>(5.0);
        target_fp_is_accurate_::<128>(10.0);
        target_fp_is_accurate_::<64>(75.0);
    }

    #[test]
    fn nothing_after_clear() {
        fn nothing_after_clear_<const N: usize>() {
            for mag in 1..6 {
                let size = 10usize.pow(mag);
                for bloom_size_mag in 6..10 {
                    let num_blocks_bytes = 1 << bloom_size_mag;
                    let sample_vals = random_numbers(size, 42);
                    let num_bits = num_blocks_bytes * 8;
                    let mut filter = BloomFilter::new_builder::<N>(num_bits)
                        .seed(&7)
                        .items(sample_vals.iter());
                    assert!(filter.num_hashes() > 0);
                    filter.clear();
                    assert!(sample_vals.iter().all(|x| !filter.contains(x)));
                    assert_eq!(block_counts(&filter).iter().sum::<u64>(), 0);
                }
            }
        }
        nothing_after_clear_::<512>();
        nothing_after_clear_::<256>();
        nothing_after_clear_::<128>();
        nothing_after_clear_::<64>();
    }

    #[test]
    fn random_inserts_always_contained() {
        fn random_inserts_always_contained_<const N: usize>() {
            for mag in 1..6 {
                let size = 10usize.pow(mag);
                for bloom_size_mag in 6..10 {
                    let num_blocks_bytes = 1 << bloom_size_mag;
                    let sample_vals = random_numbers(size, 42);
                    let num_bits = num_blocks_bytes * 8;
                    let mut filter =
                        BloomFilter::new_builder::<N>(num_bits).items(sample_vals.iter());
                    assert!(sample_vals.iter().all(|x| filter.contains(x)));
                    assert!(sample_vals.iter().all(|x| filter.insert(x)));
                }
            }
        }
        random_inserts_always_contained_::<512>();
        random_inserts_always_contained_::<256>();
        random_inserts_always_contained_::<128>();
        random_inserts_always_contained_::<64>();
    }

    #[test]
    fn test_optimal_hashes_is_optimal() {
        fn test_optimal_hashes_is_optimal_<const BLOCK_SIZE_BITS: usize, H: Seeded>() {
            let sizes = [1000, 2000, 5000, 6000, 8000, 10000];
            let mut wins = 0;
            for num_items in sizes {
                let sample_vals = random_numbers(num_items, 42);
                let num_bits = 65000 * 8;
                let filter = BloomFilter::new_builder::<BLOCK_SIZE_BITS>(num_bits)
                    .hasher(H::seeded(&[42; 16]))
                    .items(sample_vals.clone().into_iter());
                let control: HashSet<u64> = sample_vals.clone().into_iter().collect();
                let anti_vals = random_numbers(100_000, 3);
                let fp_to_beat = false_pos_rate_with_vals(&filter, &control, &anti_vals);
                let optimal_hashes = filter.num_hashes();

                for num_hashes in [optimal_hashes - 1, optimal_hashes + 1] {
                    let mut test_filter = BloomFilter::new_builder::<BLOCK_SIZE_BITS>(num_bits)
                        .hasher(H::seeded(&[42; 16]))
                        .hashes(num_hashes);
                    test_filter.extend(sample_vals.clone().into_iter());
                    let fp = false_pos_rate_with_vals(&test_filter, &control, &anti_vals);
                    wins += (fp_to_beat <= fp) as usize;
                }
            }
            assert!(wins > sizes.len() / 2);
        }
        test_optimal_hashes_is_optimal_::<512, DefaultHasher>();
        test_optimal_hashes_is_optimal_::<256, DefaultHasher>();
        test_optimal_hashes_is_optimal_::<128, DefaultHasher>();
        test_optimal_hashes_is_optimal_::<64, DefaultHasher>();
    }

    #[test]
    fn seeded_is_same() {
        let num_bits = 1 << 13;
        let sample_vals = random_strings(1000, 16, 32, 53226);
        for x in 0u8..10 {
            let seed = x as u128;
            assert_eq!(
                BloomFilter::with_num_bits(num_bits)
                    .seed(&seed)
                    .items(sample_vals.iter()),
                BloomFilter::with_num_bits(num_bits)
                    .seed(&seed)
                    .items(sample_vals.iter())
            );
            assert!(
                !(BloomFilter::with_num_bits(num_bits)
                    .seed(&(seed + 1))
                    .items(sample_vals.iter())
                    == BloomFilter::with_num_bits(num_bits)
                        .seed(&seed)
                        .items(sample_vals.iter()))
            );
        }
    }

    fn false_pos_rate_with_vals<
        'a,
        const N: usize,
        H: BuildHasher,
        X: Hash + Eq + PartialEq + 'a,
    >(
        filter: &BloomFilter<N, H>,
        control: &HashSet<X>,
        anti_vals: impl IntoIterator<Item = &'a X>,
    ) -> f64 {
        let mut total = 0;
        let mut false_positives = 0;
        for x in anti_vals.into_iter() {
            if !control.contains(x) {
                total += 1;
                false_positives += filter.contains(x) as usize;
            }
        }
        (false_positives as f64) / (total as f64)
    }

    #[test]
    fn false_pos_decrease_with_size() {
        fn false_pos_decrease_with_size_<const N: usize>() {
            let anti_vals = random_numbers(1000, 2);
            for mag in 5..6 {
                let size = 10usize.pow(mag);
                let mut prev_fp = 1.0;
                let mut prev_prev_fp = 1.0;
                for num_bits_mag in 9..22 {
                    let num_bits = 1 << num_bits_mag;
                    let sample_vals = random_numbers(size, 1);
                    let filter = BloomFilter::new_builder::<N>(num_bits).items(sample_vals.iter());
                    let control: HashSet<u64> = sample_vals.into_iter().collect();
                    let fp = false_pos_rate_with_vals(&filter, &control, &anti_vals);

                    let err = format!(
                        "size: {size:}, num_bits: {num_bits:}, {:.6}, {:?}",
                        fp,
                        filter.num_hashes(),
                    );
                    assert!(
                        fp <= prev_fp || prev_fp <= prev_prev_fp || fp < 0.01,
                        "{}",
                        err
                    ); // allows 1 data point to be higher
                    prev_prev_fp = prev_fp;
                    prev_fp = fp;
                }
            }
        }
        false_pos_decrease_with_size_::<512>();
        false_pos_decrease_with_size_::<256>();
        false_pos_decrease_with_size_::<128>();
        false_pos_decrease_with_size_::<64>();
    }

    fn assert_even_distribution(distr: &[u64], err: f64) {
        assert!(err > 0.0 && err < 1.0);
        let expected: i64 = (distr.iter().sum::<u64>() / (distr.len() as u64)) as i64;
        let thresh = (expected as f64 * err) as i64;
        for x in distr {
            let diff = (*x as i64 - expected).abs();
            assert!(diff <= thresh, "{x:?} deviates from {expected:?}");
        }
    }

    #[test]
    fn block_distribution() {
        fn block_distribution_<const N: usize>() {
            let filter = BloomFilter::new_builder::<N>(1000).items(random_numbers(1000, 1));
            assert_even_distribution(&block_counts(&filter), 0.4);
        }
        block_distribution_::<512>();
        block_distribution_::<256>();
        block_distribution_::<128>();
        block_distribution_::<64>();
    }
    #[test]
    fn block_hash_distribution() {
        fn block_hash_distribution_<H: BuildHasher + Seeded>(num_blocks: usize) {
            let mut buckets = vec![0; num_blocks];
            let hasher = H::seeded(&[42; 16]);
            for x in random_numbers(num_blocks * 10000, 42) {
                let [h1, _] = get_orginal_hashes(&hasher, &x);
                buckets[block_index(num_blocks, h1)] += 1;
            }
            assert_even_distribution(&buckets, 0.05);
        }
        for size in [2, 7, 10, 100] {
            block_hash_distribution_::<DefaultHasher>(size);
            block_hash_distribution_::<ahash::RandomState>(size);
        }
    }

    #[test]
    fn test_seeded_hash_from_hashes_depth() {
        for size in [1, 10, 100, 1000] {
            let mut rng = StdRng::seed_from_u64(524323);
            let mut h1 = rng.random_range(0..u64::MAX);
            let h2 = rng.random_range(0..u64::MAX);
            let mut seeded_hash_counts = vec![0; size];
            for _ in 0..(size * 10_000) {
                let hi = u64::next_hash(&mut h1, h2);
                seeded_hash_counts[(hi as usize) % size] += 1;
            }
            assert_even_distribution(&seeded_hash_counts, 0.05);
        }
    }

    #[test]
    fn index_hash_distribution() {
        fn index_hash_distribution_<const N: usize>(thresh_pct: f64) {
            let filter: BloomFilter<N> = BloomFilter::new_builder(1).seed(&0).hashes(1);
            let [mut h1, h2] = get_orginal_hashes(&filter.hasher, "qwerty");
            let mut counts = vec![0; N];
            let iterations = 10000 * N as u64;
            for _ in 0..iterations {
                let bit_index = BloomFilter::<N>::bit_index(&mut h1, h2);
                let index = bit_index % N;
                counts[index] += 1;
            }
            assert_even_distribution(&counts, thresh_pct);
        }
        index_hash_distribution_::<512>(0.05);
        index_hash_distribution_::<256>(0.05);
        index_hash_distribution_::<128>(0.05);
        index_hash_distribution_::<64>(0.05);
    }

    #[test]
    fn test_hash_integration() {
        fn test_hash_integration_<const N: usize, H: BuildHasher + Seeded>(thresh_pct: f64) {
            fn test_with_distr_fn<
                const N: usize,
                H: BuildHasher + Seeded,
                F: FnMut(usize) -> usize,
            >(
                f: F,
                filter: &BloomFilter<N, H>,
                thresh_pct: f64,
            ) {
                let num = 2000 * N;
                let mut counts = vec![0; N * filter.num_blocks()];
                for val in (0..num).map(f) {
                    let [mut h1, h2] = get_orginal_hashes(&filter.hasher, &val);
                    let block_index = block_index(filter.num_blocks(), h1);
                    for _ in 0..filter.num_hashes() {
                        let j = BloomFilter::<N>::bit_index(&mut h1, h2);
                        let global = block_index * N + j;
                        counts[global] += 1;
                    }
                }
                assert_even_distribution(&counts, thresh_pct);
            }
            for num_hashes in [1, 4, 8] {
                let clone_me = BloomFilter::new_builder::<N>(4)
                    .hasher(H::seeded(&[42; 16]))
                    .hashes(num_hashes);
                let mut rng = StdRng::seed_from_u64(42);
                test_with_distr_fn(
                    |_| rng.random_range(0..usize::MAX),
                    &clone_me,
                    thresh_pct,
                );
                test_with_distr_fn(|x| x * 2, &clone_me, thresh_pct);
                test_with_distr_fn(|x| x * 3, &clone_me, thresh_pct);
                test_with_distr_fn(
                    |x| x * clone_me.num_hashes() as usize,
                    &clone_me,
                    thresh_pct,
                );
                test_with_distr_fn(
                    |x| x * clone_me.num_blocks(),
                    &clone_me,
                    thresh_pct,
                );
                test_with_distr_fn(|x| x * N, &clone_me, thresh_pct);
            }
        }
        let pct = 0.1;
        test_hash_integration_::<512, DefaultHasher>(pct);
        test_hash_integration_::<256, DefaultHasher>(pct);
        test_hash_integration_::<128, DefaultHasher>(pct);
        test_hash_integration_::<64, DefaultHasher>(pct);
    }

    #[test]
    fn test_debug() {
        let filter = BloomFilter::with_num_bits(1).hashes(1);
        assert!(!format!("{:?}", filter).is_empty());
    }

    #[test]
    fn test_clone() {
        let filter = BloomFilter::with_num_bits(4).hashes(4);
        assert_eq!(filter, filter.clone());
    }

    #[test]
    fn eq_constructors_num_bits() {
        assert_eq!(
            BloomFilter::with_num_bits(4).block_size_512().hashes(4),
            BloomFilter::new_builder::<512>(4).hashes(4),
        );
        assert_eq!(
            BloomFilter::with_num_bits(4).block_size_256().hashes(4),
            BloomFilter::new_builder::<256>(4).hashes(4),
        );
        assert_eq!(
            BloomFilter::with_num_bits(4).block_size_128().hashes(4),
            BloomFilter::new_builder::<128>(4).hashes(4),
        );
        assert_eq!(
            BloomFilter::with_num_bits(4).block_size_64().hashes(4),
            BloomFilter::new_builder::<64>(4).hashes(4),
        );
    }

    #[test]
    fn eq_constructors_false_pos() {
        assert_eq!(
            BloomFilter::with_false_pos(0.4).block_size_512(),
            BloomFilter::new_with_false_pos::<512>(0.4),
        );
        assert_eq!(
            BloomFilter::with_false_pos(0.4).block_size_256(),
            BloomFilter::new_with_false_pos::<256>(0.4),
        );
        assert_eq!(
            BloomFilter::with_false_pos(0.4).block_size_128(),
            BloomFilter::new_with_false_pos::<128>(0.4),
        );
        assert_eq!(
            BloomFilter::with_false_pos(0.4).block_size_64(),
            BloomFilter::new_with_false_pos::<64>(0.4),
        );
    }

    #[test]
    fn eq_constructors_from_vec() {
        assert_eq!(
            BloomFilter::from_vec(vec![42; 42]).block_size_512(),
            BloomFilter::new_from_vec::<512>(vec![42; 42]),
        );
        assert_eq!(
            BloomFilter::from_vec(vec![42; 42]).block_size_256(),
            BloomFilter::new_from_vec::<256>(vec![42; 42]),
        );
        assert_eq!(
            BloomFilter::from_vec(vec![42; 42]).block_size_128(),
            BloomFilter::new_from_vec::<128>(vec![42; 42]),
        );
        assert_eq!(
            BloomFilter::from_vec(vec![42; 42]).block_size_64(),
            BloomFilter::new_from_vec::<64>(vec![42; 42]),
        );
    }

    #[test]
    fn test_rebuilt_from_vec() {
        for num in [1, 10, 1000, 100_000] {
            for fp in [0.1, 0.01, 0.0001, 0.0000001] {
                let items = random_numbers(num, 42);
                let b = BloomFilter::with_false_pos(fp)
                    .seed(&42)
                    .items(items.iter());
                let orig_hashes = b.num_hashes();
                let new = BloomFilter::from_vec(b.as_slice().to_vec())
                    .seed(&42)
                    .hashes(orig_hashes);
                assert!(items.iter().all(|x| new.contains(x)));
            }
        }
    }
}
