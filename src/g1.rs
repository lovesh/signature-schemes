use super::amcl_utils::{compress_g1, decompress_g1, GroupG1};
use super::errors::DecodeError;
use std::fmt;

pub struct G1Point {
    point: GroupG1,
}

impl G1Point {
    pub fn new() -> Self {
        Self {
            point: GroupG1::new(),
        }
    }

    pub fn from_raw(point: GroupG1) -> Self {
        Self { point }
    }

    pub fn add(&mut self, point: &G1Point) {
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

    pub fn as_raw(&self) -> &GroupG1 {
        &self.point
    }

    /// Instatiate the G1 point from compressed bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let pt = decompress_g1(&bytes)?;
        Ok(Self {
            point: pt,
        })
    }

    /// Export (serialize) the G1 point to compressed bytes.
    pub fn as_bytes(&mut self) -> Vec<u8> {
        compress_g1(&mut self.point)
    }
}

impl fmt::Debug for G1Point {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut temp = GroupG1::new();
        temp.copy(&self.point);
        write!(f, "{}", temp.tostring())
    }
}

impl Clone for G1Point {
    fn clone(&self) -> Self {
        let mut temp_s = GroupG1::new();
        temp_s.copy(self.as_raw());
        Self { point: temp_s }
    }
}

impl PartialEq for G1Point {
    fn eq(&self, other: &G1Point) -> bool {
        let mut clone_a = self.clone();
        let mut clone_b = other.clone();
        clone_a.as_bytes() == clone_b.as_bytes()
    }
}

impl Eq for G1Point {}

impl Default for G1Point {
    fn default() -> Self {
        Self::new()
    }
}
