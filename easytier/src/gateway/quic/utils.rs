use bytes::{BufMut, BytesMut};
use std::cmp::max;

#[derive(Debug, Clone, Copy)]
pub struct QuicBufferMargins {
    pub header: usize,
    pub trailer: usize,
}

impl From<(usize, usize)> for QuicBufferMargins {
    fn from(tuple: (usize, usize)) -> Self {
        Self {
            header: tuple.0,
            trailer: tuple.1,
        }
    }
}

impl From<QuicBufferMargins> for (usize, usize) {
    fn from(margins: QuicBufferMargins) -> Self {
        (margins.header, margins.trailer)
    }
}

#[derive(Debug)]
pub(crate) struct QuicBufferPool {
    pool: BytesMut,
    min_capacity: usize,
}

impl QuicBufferPool {
    pub(crate) fn new(min_capacity: usize) -> Self {
        Self {
            pool: BytesMut::new(),
            min_capacity,
        }
    }

    pub(crate) fn buf(&mut self, data: &[u8], margins: QuicBufferMargins) -> BytesMut {
        let (header, trailer) = margins.into();

        let len = header + data.len() + trailer;
        if len > self.pool.remaining_mut() {
            self.pool.reserve(max(len * 4, self.min_capacity));
        }
        unsafe {
            self.pool.advance_mut(len);
        }
        let mut buf = self.pool.split_to(len);
        buf[header..header + data.len()].copy_from_slice(data);
        buf
    }
}
