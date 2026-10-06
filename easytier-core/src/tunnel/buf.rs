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

    #[inline(always)]
    pub fn push(&mut self, buf: T) {
        if buf.has_remaining() {
            self.bufs.push_back(buf);
        }
    }

    #[inline(always)]
    pub fn pop(&mut self) -> Option<T> {
        self.bufs.pop_front()
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.bufs.len()
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.bufs.is_empty()
    }
}

impl<T: Buf> Extend<T> for BufList<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        self.bufs
            .extend(iter.into_iter().filter(Buf::has_remaining));
    }
}

impl<T: Buf> Buf for BufList<T> {
    #[inline]
    fn remaining(&self) -> usize {
        self.bufs.iter().map(Buf::remaining).sum()
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        self.bufs.front().map(Buf::chunk).unwrap_or_default()
    }

    #[inline]
    fn chunks_vectored<'t>(&'t self, dst: &mut [IoSlice<'t>]) -> usize {
        let mut vecs = 0;

        for buf in &self.bufs {
            let n = buf.chunks_vectored(&mut dst[vecs..]);
            vecs += n;

            if dst[vecs - n..vecs].iter().map(|s| s.len()).sum::<usize>() < buf.remaining() {
                break;
            }
        }

        vecs
    }

    #[inline]
    fn advance(&mut self, mut cnt: usize) {
        while cnt > 0 {
            let front = &mut self.bufs[0];
            let rem = front.remaining();
            front.advance(cnt.min(rem));
            if rem > cnt {
                return;
            }
            cnt -= rem;
            self.bufs.pop_front();
        }
    }

    #[inline]
    fn copy_to_bytes(&mut self, len: usize) -> Bytes {
        // Our inner buffer may have an optimized version of copy_to_bytes, and if the whole
        // request can be fulfilled by the front buffer, we can take advantage.
        if let Some(front) = self.bufs.front_mut()
            && let rem = front.remaining()
            && len <= rem
        {
            let bytes = front.copy_to_bytes(len);
            if len == rem {
                self.bufs.pop_front();
            }
            return bytes;
        }

        assert!(len <= self.remaining());
        let mut bytes = BytesMut::with_capacity(len);
        bytes.put(self.take(len));
        bytes.freeze()
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
