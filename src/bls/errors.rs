#[derive(Debug, Clone, Copy)]
pub enum SerzDeserzError {
    GroupG2BytesIncorrectSize(usize, usize),
    BigNumBytesIncorrectSize(usize, usize)
}