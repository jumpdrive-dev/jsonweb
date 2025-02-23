pub mod none_algorithm;

#[cfg(feature = "hs256")]
pub mod hs256_algorithm;

#[cfg(feature = "rs256")]
pub mod rs256_algorithm;
mod es256_algorithm;