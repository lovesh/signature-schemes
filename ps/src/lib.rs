#[cfg(all(feature = "G1G2", feature = "G2G1"))]
compile_error!("features `G1G2` and `G2G1` are mutually exclusive");

#[macro_use]
extern crate amcl_wrapper;

#[cfg(feature = "G1G2")]
type VerkeyGroup = amcl_wrapper::group_elem_g1::G1;
#[cfg(feature = "G1G2")]
type SignatureGroup = amcl_wrapper::group_elem_g2::G2;

#[cfg(feature = "G2G1")]
type VerkeyGroup = amcl_wrapper::group_elem_g2::G2;
#[cfg(feature = "G2G1")]
type SignatureGroup = amcl_wrapper::group_elem_g1::G1;