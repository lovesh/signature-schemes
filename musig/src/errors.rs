#[derive(Debug, Clone, Copy)]
pub enum SerzDeserzError {
    FieldElementBytesIncorrectSize(usize, usize),
    G1BytesIncorrectSize(usize, usize),
    G2BytesIncorrectSize(usize, usize)
}
