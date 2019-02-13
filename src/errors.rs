#[derive(Debug, PartialEq, Clone)]
pub enum DecodeError {
    BadPoint,
    IncorrectSize,
    Infinity,
}
