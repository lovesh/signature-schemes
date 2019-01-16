use super::amcl_utils::{GroupG2, G2_BYTE_SIZE};
use super::errors::DecodeError;
use std::fmt;

pub struct G2Point {
    point: GroupG2,
}

impl G2Point {
    pub fn new() -> Self {
        Self {
            point: GroupG2::new(),
        }
    }

    pub fn from_raw(point: GroupG2) -> Self {
        Self { point }
    }

    pub fn add(&mut self, point: &G2Point) {
        self.point.add(&point.point);
    }

    pub fn affine(&mut self) {
        self.point.affine();
    }

    pub fn is_infinity(&self) -> bool {
        self.point.is_infinity()
    }

    pub fn inf(&mut self) {
        self.point.inf()
    }

    pub fn as_raw(&self) -> &GroupG2 {
        &self.point
    }

    /// Instatiate the point from some bytes.
    ///
    /// TODO: detail the exact format of these bytes (e.g., compressed, etc).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != G2_BYTE_SIZE {
            return Err(DecodeError::IncorrectSize);
        }
        Ok(Self {
            point: GroupG2::frombytes(bytes),
        })
    }

    /// Export (serialize) the point to bytes.
    ///
    /// TODO: detail the exact format of these bytes (e.g., compressed, etc).
    pub fn as_bytes(&self) -> Vec<u8> {
        if self.is_infinity() {
            return vec![0; G2_BYTE_SIZE];
        };
        let mut temp = GroupG2::new();
        temp.copy(&self.point);
        let mut bytes: [u8; G2_BYTE_SIZE] = [0; G2_BYTE_SIZE];
        temp.tobytes(&mut bytes);
        bytes.to_vec()
    }
}

impl fmt::Debug for G2Point {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut temp = GroupG2::new();
        temp.copy(&self.point);
        write!(f, "{}", temp.tostring())
    }
}

impl Clone for G2Point {
    fn clone(&self) -> Self {
        let mut temp_s = GroupG2::new();
        temp_s.copy(self.as_raw());
        Self { point: temp_s }
    }
}

impl PartialEq for G2Point {
    fn eq(&self, other: &G2Point) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for G2Point {}
