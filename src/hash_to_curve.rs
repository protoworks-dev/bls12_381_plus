//! The hash-to-curve steps of [RFC 9380] for BLS12-381.
//!
//! `expand_message_xmd` (§5.3.1) and `expand_message_xof` (§5.3.2) are
//! RustCrypto's, from the `hash2curve` crate, re-exported here with the
//! [`ExpandMsg`] and [`Expander`] traits a caller implements for an expander
//! of its own. `sgn0` (§4.1), hash_to_field's reduction of uniform octets
//! (§5.2) and the simplified SWU map (§6.6.2) are this crate's, as traits over
//! its own field types.
//!
//! [RFC 9380]: https://www.rfc-editor.org/rfc/rfc9380.html

use core::num::NonZeroU16;

use elliptic_curve::array::{Array, ArraySize};
use elliptic_curve::consts::U16;
use subtle::Choice;

pub use hash2curve::{ExpandMsg, ExpandMsgXmd, ExpandMsgXof, Expander};

/// The target security level of the BLS12-381 suites, `k = 128` bits
/// (RFC 9380 §8.8.1 and §8.8.2), in octets: the `K` every [`ExpandMsg`]
/// this crate hashes through is instantiated at.
pub type SecurityLevel = U16;

/// `sgn0` of RFC 9380 §4.1: the "sign" of a field element.
pub trait Sgn0 {
    /// `1` when the element is "negative", `0` when it is not.
    fn sgn0(&self) -> Choice;
}

/// hash_to_field's reduction (RFC 9380 §5.2, steps 6 to 8): a field element
/// from the `L` uniform octets `expand_message` gives it, read as one
/// big-endian integer (OS2IP) and reduced modulo the field's characteristic.
pub trait FromOkm {
    /// `L` of RFC 9380 §5, `ceil((ceil(log2(p)) + k) / 8)` octets per base
    /// field element, times the extension degree.
    type Length: ArraySize;

    /// The field element of these uniform octets.
    fn from_okm(data: &Array<u8, Self::Length>) -> Self;
}

/// The constants of the simplified SWU map of RFC 9380 §6.6.2 over a field
/// with `q = 3 (mod 4)` (Appendix F.2.1.2).
#[derive(Debug)]
pub struct OsswuMapParams<F: 'static> {
    /// `c1 = (q - 3) / 4`, as little-endian 64-bit limbs.
    pub c1: &'static [u64],
    /// `c2 = sqrt(-Z)`.
    pub c2: F,
    /// `A'` of the curve the map lands on.
    pub map_a: F,
    /// `B'` of the curve the map lands on.
    pub map_b: F,
    /// The map's non-square `Z`.
    pub z: F,
}

/// The simplified SWU map of RFC 9380 §6.6.2.
pub trait OsswuMap: Sgn0 + Sized + 'static {
    /// The map's constants.
    const PARAMS: OsswuMapParams<Self>;

    /// The affine point `(x, y)` the map sends this element to, on the curve
    /// `A'` and `B'` define; for BLS12-381 G1 that is E1', the curve
    /// 11-isogenous to E1 (RFC 9380 §8.8.1).
    fn osswu(&self) -> (Self, Self);
}

/// `expand_message(msg, DST, N)` of `X`, read through to its last octet: the
/// `N` uniform octets hash_to_field reduces (RFC 9380 §5.2, step 2).
///
/// # Panics
///
/// When `X` refuses the DST or the length (RFC 9380 §3.1 requires a
/// nonempty DST; §5.3.1 bounds `len_in_bytes` for `expand_message_xmd`), or
/// when its expander yields fewer than `N` octets.
pub(crate) fn expand_message<X, const N: usize>(msg: &[u8], dst: &[u8]) -> [u8; N]
where
    X: ExpandMsg<SecurityLevel>,
{
    let len_in_bytes = const {
        assert!(
            N > 0 && N <= u16::MAX as usize,
            "len_in_bytes is 1 to 65535 octets"
        );
        N as u16
    };
    let len_in_bytes = NonZeroU16::new(len_in_bytes).expect("checked at compile time");
    let dst = [dst];
    let mut expander = X::expand_message(&[msg], &dst, len_in_bytes)
        .expect("expand_message refused the DST or the length");
    let mut okm = [0u8; N];
    let read = expander
        .fill_bytes(&mut okm)
        .expect("expand_message yielded no octets");
    assert_eq!(
        read, N,
        "expand_message yielded fewer octets than len_in_bytes"
    );
    okm
}
