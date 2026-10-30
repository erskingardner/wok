#![allow(non_camel_case_types)]
// Upstream denies warnings; as a path dependency this crate is linted like
// Wok's own, so a new compiler's lint would otherwise break the build.

extern crate libc;

#[cfg(unix)]
#[allow(non_camel_case_types)]
pub type mode_t = ::libc::mode_t;
#[cfg(windows)]
#[allow(non_camel_case_types)]
pub type mode_t = ::libc::c_int;

pub use constants::*;
pub use ffi::*;

mod ffi;
mod constants;
