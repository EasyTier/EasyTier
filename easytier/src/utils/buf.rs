use bytes::{BufMut, BytesMut};
use derive_more::{From, Into};
use std::mem::MaybeUninit;
use std::ptr::copy_nonoverlapping;

pub use easytier_core::tunnel::buf::BufList;

#[derive(Debug, Clone, Copy, Default, From, Into, PartialEq, Eq)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{Buf, Bytes};

    #[test]
    fn test_buf_pool_write() {
        let mut pool = BufPool::new(1024);
        let margins = BufMargins {
            header: 4,
            trailer: 2,
        };
        let data = b"hello world";
        pool.write(data, margins);
        let buf = pool.split();
        assert_eq!(buf.len(), 4 + data.len() + 2);
        assert_eq!(&buf[4..4 + data.len()], data);
    }

    #[test]
    fn test_buf_pool_writer() {
        let mut pool = BufPool::new(1024);
        let margins = BufMargins {
            header: 10,
            trailer: 6,
        };
        let mut writer = pool.writer(64, margins);
        let slice = writer.as_slice();
        assert_eq!(slice.len(), 64 - 10 - 6);
        let data = b"packet content";
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), slice.as_mut_ptr() as *mut u8, data.len());
        }
        writer.commit(data.len());
        let buf = writer.split();
        assert_eq!(buf.len(), 10 + data.len() + 6);
        assert_eq!(&buf[10..10 + data.len()], data);
    }
}
