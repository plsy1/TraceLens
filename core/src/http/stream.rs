#[derive(Debug, Default)]
pub struct StreamReassembler {
    buffer: Vec<u8>,
}

impl StreamReassembler {
    pub fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }
}
