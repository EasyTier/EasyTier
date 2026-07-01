use bytes::{Buf, BufMut, Bytes};
use derive_more::{From, Into};
use std::collections::VecDeque;
use std::io::IoSlice;
use std::mem::MaybeUninit;
use std::ptr::copy_nonoverlapping;
use tokio_util::bytes::BytesMut;

#[derive(Debug, Clone, Copy, Default, From, Into)]
pub struct BufMargins {
    pub header: usize,
    pub trailer: usize,
}

impl BufMargins {
    #[inline(always)]
    pub fn size(&self) -> usize {
        self.header + self.trailer
    }
}

#[derive(Debug)]
pub struct BufPool {
    pool: BytesMut,
    pub min_capacity: usize,
}

impl BufPool {
    #[inline(always)]
    pub fn new(min_capacity: usize) -> Self {
        Self {
            pool: BytesMut::with_capacity(min_capacity),
            min_capacity,
        }
    }

    #[inline(always)]
    pub fn reserve(&mut self, additional: usize) {
        if self.pool.capacity() - self.pool.len() < additional {
            self.pool.reserve(additional.max(self.min_capacity));
        }
    }

    #[inline(always)]
    pub fn split(&mut self) -> BytesMut {
        self.pool.split()
    }

    #[inline]
    pub fn write(&mut self, chunk: &[u8], margins: BufMargins) {
        let len = margins.size() + chunk.len();
        self.reserve(len);
        unsafe {
            copy_nonoverlapping(
                chunk.as_ptr(),
                self.pool.chunk_mut().as_mut_ptr().add(margins.header),
                chunk.len(),
            );
            self.pool.advance_mut(len);
        }
    }

    #[inline(always)]
    pub fn buf(&mut self, chunk: &[u8], margins: BufMargins) -> BytesMut {
        self.write(chunk, margins);
        self.pool.split()
    }

    #[inline(always)]
    pub fn writer(&mut self, capacity: usize, margins: BufMargins) -> BufPoolWriter<'_> {
        assert!(capacity >= margins.size());
        self.reserve(capacity);
        BufPoolWriter {
            pool: self,
            capacity,
            margins,
        }
    }
}

#[derive(Debug)]
pub struct BufPoolWriter<'t> {
    pool: &'t mut BufPool,
    capacity: usize,
    margins: BufMargins,
}

impl<'t> BufPoolWriter<'t> {
    #[inline(always)]
    pub fn reserve(&mut self, additional: usize) {
        if self.capacity < additional {
            self.pool.reserve(additional);
            self.capacity += additional;
        }
    }

    #[inline(always)]
    pub fn split(&mut self) -> BytesMut {
        self.pool.split()
    }

    #[inline(always)]
    pub fn as_slice(&mut self) -> &mut [MaybeUninit<u8>] {
        unsafe {
            self.pool
                .pool
                .spare_capacity_mut()
                .get_unchecked_mut(self.margins.header..self.capacity - self.margins.trailer)
        }
    }

    #[inline(always)]
    pub fn commit(&mut self, written: usize) {
        let len = self.margins.size() + written;
        assert!(self.capacity >= len);
        self.capacity -= len;
        unsafe {
            self.pool.pool.advance_mut(len);
        }
    }
}

#[derive(Debug, Default)]
pub struct BufList<T> {
    bufs: VecDeque<T>,
}

impl<T: Buf> BufList<T> {
    pub fn new() -> BufList<T> {
        BufList {
            bufs: VecDeque::new(),
        }
    }

    #[inline]
    pub fn push(&mut self, buf: T) {
        debug_assert!(buf.has_remaining());
        self.bufs.push_back(buf);
    }

    #[inline]
    pub fn pop(&mut self) -> Option<T> {
        self.bufs.pop_front()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.bufs.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bufs.is_empty()
    }
}

impl<T: Buf> Extend<T> for BufList<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        self.bufs.extend(
            iter.into_iter()
                .inspect(|buf| debug_assert!(buf.has_remaining())),
        );
    }
}

impl<T: Buf> Buf for BufList<T> {
    #[inline]
    fn remaining(&self) -> usize {
        self.bufs.iter().map(|buf| buf.remaining()).sum()
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        self.bufs.front().map(Buf::chunk).unwrap_or_default()
    }

    #[inline]
    fn chunks_vectored<'t>(&'t self, dst: &mut [IoSlice<'t>]) -> usize {
        if dst.is_empty() {
            return 0;
        }
        let mut vecs = 0;
        for buf in &self.bufs {
            vecs += buf.chunks_vectored(&mut dst[vecs..]);
            if vecs == dst.len() {
                break;
            }
        }
        vecs
    }

    #[inline]
    fn advance(&mut self, mut cnt: usize) {
        while cnt > 0 {
            {
                let front = &mut self.bufs[0];
                let rem = front.remaining();
                if rem > cnt {
                    front.advance(cnt);
                    return;
                } else {
                    front.advance(rem);
                    cnt -= rem;
                }
            }
            self.bufs.pop_front();
        }
    }

    #[inline]
    fn copy_to_bytes(&mut self, len: usize) -> Bytes {
        // Our inner buffer may have an optimized version of copy_to_bytes, and if the whole
        // request can be fulfilled by the front buffer, we can take advantage.
        match self.bufs.front_mut() {
            Some(front) if front.remaining() == len => {
                let b = front.copy_to_bytes(len);
                self.bufs.pop_front();
                b
            }
            Some(front) if front.remaining() > len => front.copy_to_bytes(len),
            _ => {
                assert!(len <= self.remaining(), "`len` greater than remaining");
                let mut bm = BytesMut::with_capacity(len);
                bm.put(self.take(len));
                bm.freeze()
            }
        }
    }
}
