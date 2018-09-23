use super::amcl_utils::{
    GroupG1,
    G1_BYTE_SIZE,
};
use super::errors::DecodeError;
use std::fmt;

pub struct G1Point {
    point: GroupG1,
}

impl G1Point {
    pub fn new() -> Self {
        Self{
            point: GroupG1::new()
        }
    }

    pub fn from_raw(point: GroupG1) -> Self {
        Self {
            point
        }
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

    /// Instatiate the point from some bytes.
    ///
    /// TODO: detail the exact format of these bytes (e.g., compressed, etc).
    pub fn from_bytes(bytes: &[u8])
        -> Result<Self, DecodeError>
    {
        if bytes.len() != G1_BYTE_SIZE {
            return Err(DecodeError::IncorrectSize)
        }
        Ok(Self {
            point: GroupG1::frombytes(bytes)
        })
    }

    /// Export (serialize) the point to bytes.
    ///
    /// TODO: detail the exact format of these bytes (e.g., compressed, etc).
    pub fn as_bytes(&self) -> Vec<u8> {
        if self.is_infinity() {
            return vec![0; G1_BYTE_SIZE]
        };
        let mut temp = GroupG1::new();
        temp.copy(&self.point);
        let mut bytes: [u8; G1_BYTE_SIZE] = [0; G1_BYTE_SIZE];
        temp.tobytes(&mut bytes, false);
        bytes.to_vec()
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
        Self {
            point: temp_s
        }
    }
}
