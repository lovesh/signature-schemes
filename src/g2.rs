use super::amcl_utils::{compress_g2, decompress_g2, GroupG2};
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

    /// Instatiate the point from compressed bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let pt = decompress_g2(&bytes)?;
        Ok(Self {
            point: pt,
        })
    }

    /// Export (serialize) the point to compressed bytes.
    pub fn as_bytes(&mut self) -> Vec<u8> {
        compress_g2(&mut self.point)
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
        let mut clone_a = self.clone();
        let mut clone_b = other.clone();
        clone_a.as_bytes() == clone_b.as_bytes()
    }
}

impl Eq for G2Point {}

impl Default for G2Point {
    fn default() -> Self {
        Self::new()
    }
}
