//! RFC 9380 vectors through the crate's public hash-to-curve surface:
//! `expand_message_xmd` over SHA-256 with a short and a 256-octet DST
//! (Appendix K.1, K.2), `expand_message_xof` over SHAKE256 (Appendix K.6),
//! and `hash_to_curve` for BLS12381G1_XMD:SHA-256_SSWU_RO_ (Appendix J.9.1).
//!
//! `fixtures/rfc9380-appendix-j9.1-k1-k2-k6.json` holds the appendices'
//! values as printed in the plain-text RFC 9380 (August 2023), the hex lines a
//! value wraps over joined and nothing else changed.

#![cfg(feature = "groups")]

use core::num::NonZeroU16;

use bls12_381_plus::elliptic_curve::consts::{U16, U32};
use bls12_381_plus::hash_to_curve::{ExpandMsg, ExpandMsgXmd, ExpandMsgXof, Expander};
use bls12_381_plus::{G1Affine, G1Projective, G2Projective};
use serde_json::Value;
use sha2::Sha256;
use shake::Shake256;

fn vectors() -> Value {
    serde_json::from_str(include_str!("fixtures/rfc9380-appendix-j9.1-k1-k2-k6.json")).unwrap()
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap()
}

/// Every case of one Appendix K section through the expander `expand`, which
/// returns `len_in_bytes` octets of `msg` under `dst`.
fn check_appendix_k(
    section: &str,
    hash: &str,
    k: &str,
    expand: impl Fn(&[u8], &[u8], NonZeroU16) -> Vec<u8>,
) {
    let suite = &vectors()[section];
    assert_eq!(text(&suite["hash"]), hash);
    // The appendix prints k as a decimal string, as the fixture keeps it.
    assert_eq!(text(&suite["k"]), k);
    let dst = text(&suite["DST"]).as_bytes();
    let cases = suite["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 10);
    for case in cases {
        let msg = text(&case["msg"]).as_bytes();
        let len =
            u16::from_str_radix(text(&case["len_in_bytes"]).trim_start_matches("0x"), 16).unwrap();
        let expected = hex::decode(text(&case["uniform_bytes"])).unwrap();
        assert_eq!(usize::from(len), expected.len());
        let actual = expand(msg, dst, NonZeroU16::new(len).unwrap());
        assert_eq!(
            hex::encode(actual),
            hex::encode(expected),
            "{section} {case}"
        );
    }
}

/// `len_in_bytes` octets from `X`, read in one call.
fn expand_with<X: ExpandMsg<K>, K>(msg: &[u8], dst: &[u8], len: NonZeroU16) -> Vec<u8> {
    let dsts = [dst];
    let mut expander = X::expand_message(&[msg], &dsts, len).unwrap();
    let mut out = vec![0u8; usize::from(len.get())];
    assert_eq!(expander.fill_bytes(&mut out).unwrap(), out.len());
    out
}

#[test]
fn expand_message_xmd_sha256_meets_appendix_k_1() {
    check_appendix_k(
        "K.1",
        "SHA256",
        "128",
        expand_with::<ExpandMsgXmd<Sha256>, U16>,
    );
}

#[test]
fn expand_message_xmd_sha256_long_dst_meets_appendix_k_2() {
    check_appendix_k(
        "K.2",
        "SHA256",
        "128",
        expand_with::<ExpandMsgXmd<Sha256>, U16>,
    );
}

#[test]
fn expand_message_xof_shake256_meets_appendix_k_6() {
    check_appendix_k(
        "K.6",
        "SHAKE256",
        "256",
        expand_with::<ExpandMsgXof<Shake256>, U32>,
    );
}

#[test]
fn hash_to_curve_g1_meets_appendix_j_9_1() {
    let suite = &vectors()["J.9.1"];
    assert_eq!(text(&suite["suite"]), "BLS12381G1_XMD:SHA-256_SSWU_RO_");
    let dst = text(&suite["dst"]).as_bytes();
    let cases = suite["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 5);
    for case in cases {
        let point = G1Affine::from(G1Projective::hash::<ExpandMsgXmd<Sha256>>(
            text(&case["msg"]).as_bytes(),
            dst,
        ));
        let uncompressed = point.to_uncompressed();
        assert_eq!(hex::encode(&uncompressed[..48]), text(&case["P.x"]));
        assert_eq!(hex::encode(&uncompressed[48..]), text(&case["P.y"]));
    }
}

/// An `expand_message` of the caller's own: it hands back the octets it is
/// given as the message, in order, and ignores the DST.
struct Passthrough;

struct PassthroughReader {
    octets: Vec<u8>,
    offset: usize,
}

#[derive(Debug)]
struct Never;

impl core::fmt::Display for Never {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("never")
    }
}

impl core::error::Error for Never {}

impl ExpandMsg<U16> for Passthrough {
    type Hash = ();
    type Expander<'dst> = PassthroughReader;
    type Error = Never;

    fn expand_message(
        msg: &[&[u8]],
        _dst: &[&[u8]],
        _len_in_bytes: NonZeroU16,
    ) -> Result<PassthroughReader, Never> {
        Ok(PassthroughReader {
            octets: msg.concat(),
            offset: 0,
        })
    }
}

impl Expander for PassthroughReader {
    fn fill_bytes(
        &mut self,
        okm: &mut [u8],
    ) -> Result<usize, bls12_381_plus::elliptic_curve::Error> {
        let n = okm.len().min(self.octets.len() - self.offset);
        okm[..n].copy_from_slice(&self.octets[self.offset..self.offset + n]);
        self.offset += n;
        Ok(n)
    }
}

/// `encode` takes an expander the caller implements: the octets
/// `expand_message_xmd` gives, handed back unchanged, map to the point
/// `encode` reaches through `expand_message_xmd` itself.
#[test]
fn encode_takes_a_caller_implemented_expander() {
    const G1_DST: &[u8] = b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_NU_";
    const G2_DST: &[u8] = b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_NU_";
    for msg in [&b""[..], b"abc", b"abcdef0123456789"] {
        let u = expand_with::<ExpandMsgXmd<Sha256>, U16>(msg, G1_DST, NonZeroU16::new(64).unwrap());
        assert_eq!(
            G1Projective::encode::<Passthrough>(&u, &[]),
            G1Projective::encode::<ExpandMsgXmd<Sha256>>(msg, G1_DST),
        );
        let u =
            expand_with::<ExpandMsgXmd<Sha256>, U16>(msg, G2_DST, NonZeroU16::new(128).unwrap());
        assert_eq!(
            G2Projective::encode::<Passthrough>(&u, &[]),
            G2Projective::encode::<ExpandMsgXmd<Sha256>>(msg, G2_DST),
        );
    }
}

/// A short expander is refused rather than read as zeros.
#[test]
#[should_panic(expected = "fewer octets")]
fn encode_refuses_an_expander_that_runs_short() {
    let _ = G1Projective::encode::<Passthrough>(&[0u8; 63], &[]);
}

/// RFC 9380 §3.1: a DST is nonempty, and hashing under an empty one is
/// refused.
#[test]
#[should_panic(expected = "refused")]
fn hash_refuses_an_empty_dst() {
    let _ = G1Projective::hash::<ExpandMsgXmd<Sha256>>(b"abc", b"");
}
