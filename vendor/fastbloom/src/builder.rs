use crate::{BloomFilter, BuildHasher, DefaultHasher};
use std::f64::consts::LN_2;
use std::hash::Hash;

use crate::sparse_hash;

/// A Bloom filter builder with an immutable number of bits.
///
/// This type can be used to construct an instance of [`BloomFilter`] via the builder pattern.
///
/// # Examples
/// ```
/// use fastbloom::BloomFilter;
///
/// let builder = BloomFilter::with_num_bits(1024);
/// let builder = BloomFilter::from_vec(vec![0; 8]);
/// ```
#[derive(Debug, Clone)]
pub struct BuilderWithBits<const BLOCK_SIZE_BITS: usize = 512, S = DefaultHasher> {
    pub(crate) data: Vec<u64>,
    pub(crate) hasher: S,
}

impl<const BLOCK_SIZE_BITS: usize, S: BuildHasher> PartialEq
    for BuilderWithBits<BLOCK_SIZE_BITS, S>
{
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}
impl<const BLOCK_SIZE_BITS: usize, S: BuildHasher> Eq for BuilderWithBits<BLOCK_SIZE_BITS, S> {}

impl<const BLOCK_SIZE_BITS: usize> BuilderWithBits<BLOCK_SIZE_BITS> {
    /// Sets the seed for this builder. The later constructed [`BloomFilter`]
    /// will use this seed when hashing items.
    ///
    /// # Examples
    ///
    /// ```
    /// use fastbloom::BloomFilter;
    ///
    /// let bloom = BloomFilter::with_num_bits(1024).seed(&1).hashes(4);
    /// ```
    pub fn seed(mut self, seed: &u128) -> Self {
        self.hasher = DefaultHasher::seeded(&seed.to_be_bytes());
        self
    }
}

impl<const BLOCK_SIZE_BITS: usize, S: BuildHasher> BuilderWithBits<BLOCK_SIZE_BITS, S> {
    /// Sets the hasher for this builder. The later constructed [`BloomFilter`] will use
    /// this hasher when inserting and checking items.
    ///
    /// # Examples
    ///
    /// ```
    /// use fastbloom::BloomFilter;
    /// use ahash::RandomState;
    ///
    /// let bloom = BloomFilter::with_num_bits(1024).hasher(RandomState::default()).hashes(4);
    /// ```
    pub fn hasher<H: BuildHasher>(self, hasher: H) -> BuilderWithBits<BLOCK_SIZE_BITS, H> {
        BuilderWithBits::<BLOCK_SIZE_BITS, H> {
            data: self.data,
            hasher,
        }
    }

    /// "Consumes" this builder, using the provided `num_hashes` to return an
    /// empty [`BloomFilter`].
    ///
    /// # Examples
    /// ```
    /// use fastbloom::BloomFilter;
    ///
    /// let bloom = BloomFilter::with_num_bits(1024).hashes(4);
    /// ```
    pub fn hashes(self, num_hashes: u32) -> BloomFilter<BLOCK_SIZE_BITS, S> {
        self.hashes_f(num_hashes as f64)
    }

    /// To generate ~`total_num_hashes` we'll use a combination of traditional index derived from hashes and "sparse hashes".
    /// sparse hashes's are per u64 in the block, and for that u64 represent some indexes already set.
    /// "rounds" are the amount of work/iterations we need to do to get a sparse hash.
    /// For more on sparse hashes, see "BloomFilter::sparse_hash".
    ///
    /// For example, if our target total hashes 40, and we have a block of two u64s,
    /// we'll require ~40 bits (ignoring probability collisions for simplicity in this example) set across the two u64s.
    /// for each u64 in the block, generate two sparse hashes each with about 16 bits set (2 rounds each).
    /// then calcuate 8 bit indexes from the hash to cover the remaining. 16 + 16 + 8 = 40.
    /// the total work here is 4 rounds + 8 hashes, instead of 40 hashes.
    ///
    /// Note:
    /// - the min number of rounds is 1, generating around ~32 bits, which is the max entropy in the u64.
    /// - the max number of rounds is ~4. That produces a sparse hash of ~4 bits set (1/2^4), at which point we may as well calculate 4 bit indexes normally.
    fn hashes_f(self, total_num_hashes: f64) -> BloomFilter<BLOCK_SIZE_BITS, S> {
        let total_num_hashes = total_num_hashes.floor();
        let (num_hashes, num_rounds) =
            sparse_hash::optimize_hashing(total_num_hashes, BLOCK_SIZE_BITS);

        BloomFilter {
            bits: self.data.into(),
            target_hashes: total_num_hashes as u64,
            num_hashes,
            num_rounds,
            hasher: self.hasher,
        }
    }

    /// "Consumes" this builder, using the provided `expected_num_items` to return an
    /// empty [`BloomFilter`]. The number of hashes is optimized based on `expected_num_items`
    /// to maximize Bloom filter accuracy (minimize false positives chance on [`BloomFilter::contains`]).
    /// More or less than `expected_num_items` may be inserted into [`BloomFilter`].
    ///
    /// # Examples
    ///
    /// ```
    /// use fastbloom::BloomFilter;
    ///
    /// let bloom = BloomFilter::with_num_bits(1024).expected_items(500);
    /// ```
    pub fn expected_items(self, expected_num_items: usize) -> BloomFilter<BLOCK_SIZE_BITS, S> {
        let u64s_per_block = (BLOCK_SIZE_BITS / 64) as f64;
        let num_blocks = (self.data.len() as f64 / u64s_per_block).ceil();
        let items_per_block = expected_num_items as f64 / num_blocks;
        let num_hashes = BloomFilter::<BLOCK_SIZE_BITS>::optimal_hashes_f(items_per_block);
        self.hashes_f(num_hashes)
    }

    /// "Consumes" this builder and constructs a [`BloomFilter`] containing
    /// all values in `items`. Like [`BuilderWithBits::expected_items`], the number of hashes per item
    /// is optimized based on `items.len()` to maximize Bloom filter accuracy
    /// (minimize false positives chance on [`BloomFilter::contains`]).
    ///
    /// # Examples
    ///
    /// ```
    /// use fastbloom::BloomFilter;
    ///
    /// let bloom = BloomFilter::with_num_bits(1024).items([1, 2, 3]);
    /// ```
    pub fn items<I: IntoIterator<IntoIter = impl ExactSizeIterator<Item = impl Hash>>>(
        self,
        items: I,
    ) -> BloomFilter<BLOCK_SIZE_BITS, S> {
        let into_iter = items.into_iter();
        let mut filter = self.expected_items(into_iter.len());
        filter.extend(into_iter);
        filter
    }
}

fn optimal_size(items_count: f64, fp_p: f64) -> usize {
    let log2_2 = LN_2 * LN_2;
    let result = 8 * ((items_count) * f64::ln(fp_p) / (-8.0 * log2_2)).ceil() as usize;
    std::cmp::max(result, 512)
}

/// A Bloom filter builder with an immutable false positive rate.
///
/// This type can be used to construct an instance of [`BloomFilter`] via the builder pattern.
///
/// # Examples
///
/// ```
/// use fastbloom::BloomFilter;
///
/// let builder = BloomFilter::with_false_pos(0.01);
/// ```
#[derive(Debug, Clone)]
pub struct BuilderWithFalsePositiveRate<const BLOCK_SIZE_BITS: usize = 512, S = DefaultHasher> {
    pub(crate) desired_fp_rate: f64,
    pub(crate) hasher: S,
}

impl<const BLOCK_SIZE_BITS: usize, S: BuildHasher> PartialEq
    for BuilderWithFalsePositiveRate<BLOCK_SIZE_BITS, S>
{
    fn eq(&self, other: &Self) -> bool {
        self.desired_fp_rate == other.desired_fp_rate
    }
}
impl<const BLOCK_SIZE_BITS: usize, S: BuildHasher> Eq
    for BuilderWithFalsePositiveRate<BLOCK_SIZE_BITS, S>
{
}

impl<const BLOCK_SIZE_BITS: usize> BuilderWithFalsePositiveRate<BLOCK_SIZE_BITS> {
    /// Sets the seed for this builder. The later constructed [`BloomFilter`]
    /// will use this seed when hashing items.
    ///
    /// # Examples
    ///
    /// ```
    /// use fastbloom::BloomFilter;
    ///
    /// let bloom = BloomFilter::with_false_pos(0.001).seed(&1).expected_items(100);
    /// ```
    pub fn seed(mut self, seed: &u128) -> Self {
        self.hasher = DefaultHasher::seeded(&seed.to_be_bytes());
        self
    }
}

impl<const BLOCK_SIZE_BITS: usize, S: BuildHasher>
    BuilderWithFalsePositiveRate<BLOCK_SIZE_BITS, S>
{
    /// Sets the hasher for this builder. The later constructed [`BloomFilter`] will use
    /// this hasher when inserting and checking items.
    ///
    /// # Examples
    ///
    /// ```
    /// use fastbloom::BloomFilter;
    /// use ahash::RandomState;
    ///
    /// let bloom = BloomFilter::with_false_pos(0.001).hasher(RandomState::default()).expected_items(100);
    /// ```
    pub fn hasher<H: BuildHasher>(
        self,
        hasher: H,
    ) -> BuilderWithFalsePositiveRate<BLOCK_SIZE_BITS, H> {
        BuilderWithFalsePositiveRate::<BLOCK_SIZE_BITS, H> {
            desired_fp_rate: self.desired_fp_rate,
            hasher,
        }
    }

    /// "Consumes" this builder, using the provided `expected_num_items` to return an
    /// empty [`BloomFilter`]. The number of hashes and underlying memory is optimized based on `expected_num_items`
    /// to meet the desired false positive rate.
    /// More or less than `expected_num_items` may be inserted into [`BloomFilter`].
    ///
    /// # Examples
    ///
    /// ```
    /// use fastbloom::BloomFilter;
    ///
    /// let bloom = BloomFilter::with_false_pos(0.001).expected_items(500);
    /// ```
    pub fn expected_items(self, expected_num_items: usize) -> BloomFilter<BLOCK_SIZE_BITS, S> {
        let num_bits = optimal_size(expected_num_items as f64, self.desired_fp_rate);
        BloomFilter::new_builder::<BLOCK_SIZE_BITS>(num_bits)
            .hasher(self.hasher)
            .expected_items(expected_num_items)
    }

    /// "Consumes" this builder and constructs a [`BloomFilter`] containing
    /// all values in `items`. Like [`BuilderWithFalsePositiveRate::expected_items`], the number of hashes per item
    /// and underlying memory is optimized based on `items.len()` to meet the desired false positive rate.
    ///
    /// # Examples
    ///
    /// ```
    /// use fastbloom::BloomFilter;
    ///
    /// let bloom = BloomFilter::with_false_pos(0.001).items([1, 2, 3]);
    /// ```
    pub fn items<I: IntoIterator<IntoIter = impl ExactSizeIterator<Item = impl Hash>>>(
        self,
        items: I,
    ) -> BloomFilter<BLOCK_SIZE_BITS, S> {
        let into_iter = items.into_iter();
        let mut filter = self.expected_items(into_iter.len());
        filter.extend(into_iter);
        filter
    }
}

macro_rules! impl_builder_block_size {
    ($($size:literal = $fn_name:ident),* $(,)*) => (
        $(
            impl<const BLOCK_SIZE_BITS: usize, S: BuildHasher> BuilderWithFalsePositiveRate<BLOCK_SIZE_BITS, S> {
                #[doc = concat!("Set the block size of the Bloom filter to ", stringify!($size), " bits.")]
                #[doc = concat!("The underlying bit vector size will be rounded up to be a multiple of the block size.")]
                #[doc = "# Example"]
                #[doc = "```"]
                #[doc = "use fastbloom::BloomFilter;"]
                #[doc = concat!("let builder = BloomFilter::with_false_pos(0.01).block_size_", stringify!($size), "();")]
                #[doc = "```"]
                pub fn $fn_name(self) -> BuilderWithFalsePositiveRate<$size, S> {
                    BuilderWithFalsePositiveRate::<$size, S> {
                        desired_fp_rate: self.desired_fp_rate,
                        hasher: self.hasher,
                    }
                }
            }

            impl<const BLOCK_SIZE_BITS: usize, S: BuildHasher> BuilderWithBits<BLOCK_SIZE_BITS, S> {
                #[doc = concat!("Set the block size of the Bloom filter to ", stringify!($size), " bits.")]
                #[doc = concat!("The underlying bit vector size will be rounded up to be a multiple of the block size.")]
                #[doc = "# Example"]
                #[doc = "```"]
                #[doc = "use fastbloom::BloomFilter;"]
                #[doc = concat!("let builder = BloomFilter::with_num_bits(1000).block_size_", stringify!($size), "();")]
                #[doc = "```"]
                pub fn $fn_name(self) -> BuilderWithBits<$size, S> {
                    BuilderWithBits::<$size, S> {
                        data: self.data,
                        hasher: self.hasher,
                    }
                }
            }
        )*
    )
}

impl_builder_block_size!(
    64 = block_size_64,
    128 = block_size_128,
    256 = block_size_256,
    512 = block_size_512,
);

#[cfg(test)]
mod for_accuracy_tests {
    use crate::BloomFilter;

    #[test]
    fn data_size() {
        let size_bits = 512 * 1000;
        let bloom = BloomFilter::with_num_bits(size_bits)
            .block_size_512()
            .hashes(4);
        assert_eq!(bloom.as_slice().len() * 64, size_bits);
        assert_eq!(bloom.num_blocks(), size_bits / 512);
        let bloom = BloomFilter::with_num_bits(size_bits)
            .block_size_256()
            .hashes(4);
        assert_eq!(bloom.as_slice().len() * 64, size_bits);
        assert_eq!(bloom.num_blocks(), size_bits / 256);
        let bloom = BloomFilter::with_num_bits(size_bits)
            .block_size_128()
            .hashes(4);
        assert_eq!(bloom.as_slice().len() * 64, size_bits);
        assert_eq!(bloom.num_blocks(), size_bits / 128);
        let bloom = BloomFilter::with_num_bits(size_bits)
            .block_size_64()
            .hashes(4);
        assert_eq!(bloom.as_slice().len() * 64, size_bits);
        assert_eq!(bloom.num_blocks(), size_bits / 64);
    }

    #[test]
    fn specified_hashes() {
        for num_hashes in 1..1000 {
            assert_eq!(
                num_hashes,
                BloomFilter::with_num_bits(1)
                    .hashes(num_hashes)
                    .num_hashes()
            );
            assert_eq!(
                num_hashes,
                BloomFilter::with_num_bits(1)
                    .block_size_512()
                    .hashes(num_hashes)
                    .num_hashes()
            );
            assert_eq!(
                num_hashes,
                BloomFilter::with_num_bits(1)
                    .block_size_256()
                    .hashes(num_hashes)
                    .num_hashes()
            );
            assert_eq!(
                num_hashes,
                BloomFilter::with_num_bits(1)
                    .block_size_128()
                    .hashes(num_hashes)
                    .num_hashes()
            );
            assert_eq!(
                num_hashes,
                BloomFilter::with_num_bits(1)
                    .block_size_64()
                    .hashes(num_hashes)
                    .num_hashes()
            );
        }
    }

    #[test]
    fn correct_size() {
        for num_bits in 1..10000 {
            let b = BloomFilter::with_num_bits(num_bits).hashes(1);
            assert_eq!(b.num_bits() % 512, 0);
            let b = BloomFilter::with_num_bits(num_bits)
                .block_size_512()
                .hashes(1);
            assert_eq!(b.num_bits() % 512, 0);
            let b = BloomFilter::with_num_bits(num_bits)
                .block_size_256()
                .hashes(1);
            assert_eq!(b.num_bits() % 256, 0);
            let b = BloomFilter::with_num_bits(num_bits)
                .block_size_128()
                .hashes(1);
            assert_eq!(b.num_bits() % 128, 0);
            let b = BloomFilter::with_num_bits(num_bits)
                .block_size_64()
                .hashes(1);
            assert_eq!(b.num_bits() % 64, 0);
        }
    }
}

#[cfg(test)]
mod for_size_tests {
    use crate::BloomFilter;

    #[test]
    fn test_size() {
        let _: BloomFilter<512> = BloomFilter::new_with_false_pos(0.0001).expected_items(10000);
    }
}
