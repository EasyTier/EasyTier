use std::collections::VecDeque;
use std::io::IoSlice;

use bytes::{Buf, BufMut, Bytes, BytesMut};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buf_list() {
        let mut list = BufList::new();
        list.push(Bytes::from_static(b"hello "));
        list.push(Bytes::from_static(b"world"));
        assert_eq!(list.remaining(), 11);
        let bytes = list.copy_to_bytes(11);
        assert_eq!(&bytes[..], b"hello world");
        assert_eq!(list.remaining(), 0);
    }
}
