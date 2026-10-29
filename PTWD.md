# The `ptwd` branch

This branch is `bls12_381_plus` 0.9.0 with `elliptic-curve` 0.13, and with it
`crypto-bigint` 0.5, taken out of the dependency graph. Its releases are tagged
`v0.9.0-ptwd.N`, and the package version says the same.

## Why

[RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html):
`crypto-bigint` before 0.7.6 has secret-dependent timing in subtraction,
division and Montgomery multiplication. 0.9.0 depends on `elliptic-curve`
0.13.8 unconditionally, with its `hash2curve` and `hazmat` features, and that
release depends on `crypto-bigint` 0.5.5. No release of the 0.5 line is fixed.

The field and scalar arithmetic here never ran on `crypto-bigint`; it is the
crate's own limb code. The 0.13 line was there for its integer types, for
the trait impls built on them, and for `expand_message`.

## What changed

- **`expand_message`** comes from RustCrypto's `hash2curve` 0.14, re-exported
  as `bls12_381_plus::hash_to_curve::{ExpandMsg, ExpandMsgXmd, ExpandMsgXof,
  Expander}` and as the crate `bls12_381_plus::hash2curve`. Its `ExpandMsg`
  takes the target security level as a type parameter.
  `G1Projective::{hash, encode}`, `G2Projective::{hash, encode}` and
  `Scalar::hash` take any `X: ExpandMsg<SecurityLevel>`, where
  `SecurityLevel` is `U16`: k = 128 bits, RFC 9380 §8.8. A caller's own
  expander implements that trait. The hashes are those of the `digest` 0.11
  line, so `sha2` 0.11 and `shake` 0.1.
- **The hash-to-curve traits** that `hash2curve` 0.14 no longer carries are
  the crate's own, in `bls12_381_plus::hash_to_curve`:
  - `Sgn0`, for `Fp` and `Fp2`;
  - `FromOkm`, for `Fp`, over `elliptic_curve::array::Array<u8, U64>`;
  - `OsswuMap` with `OsswuMapParams`, for `Fp`.
  
  The G1 isogeny and `map_to_curve` are crate-internal.
- **`Fp2::sgn0`** is now RFC 9380 §4.1's `sign_0 OR (zero_0 AND sign_1)` in
  constant time, where it used to branch on whether `c0` is zero.
- **`Scalar`'s `IsHigh`** compares the canonical integer with `(q - 1) / 2`.
  It used to compare the Montgomery limbs, which gave the wrong answer for,
  among others, 3 and `(q - 1) / 2`.
- **Removed**, because each was built on `elliptic-curve` 0.13 or
  `crypto-bigint` 0.5 types:
  - the `elliptic_curve_013` re-export;
  - the 0.13 `Curve`, `PrimeCurve`, `PointCompression` and `FieldBytesEncoding`
    impls for `Bls12381G1` and `Bls12381G2`; the 0.14 ones remain;
  - `ScalarPrimitive` conversions;
  - `From`/`Into` `U256`, `U384` and `U512`;
  - the 0.13 `Reduce`, `FromUintUnchecked`, `Invert` and `IsHigh` impls on
    `Scalar`;
  - the 0.13 `AffineCoordinates`, `MulByGenerator` and `LinearCombination`
    impls on the G1 and G2 types.
  
  `From<[u8; 48]> for Scalar` keeps its meaning, now read straight from the
  octets.
- **The 0.14 `AffineCoordinates::FieldRepr`** is `elliptic_curve::array::Array`
  in place of 0.13's `GenericArray`.
- **The simplified SWU map onto E2'** takes `inv0` of `Z^2 * u^4 + Z * u^2`
  and sets `x1 = B' / (Z * A')` where that is zero, as RFC 9380 §6.6.2 asks.
  It used to take `invert().unwrap()`, which panicked at `u = 0`, and to
  test `x1 == 0` for the exceptional case, a condition no `u` in Fp2 meets.
- **Both isogeny maps** return the identity where a denominator is zero, as
  RFC 9380 §6.6.3 requires. They used to `invert().unwrap()` it and panic.
  G1's 11-isogeny has five such `x'` in Fp, and G2's 3-isogeny has
  `x' = -6 + 6 * I`.
- **MSRV** is 1.88, the `rust-version` of `sha2` 0.11.1.

## Proof

- `tests/rfc9380.rs` checks the public surface against RFC 9380:
  - Appendix K.1 and K.2: `expand_message_xmd` over SHA-256, with the short
    DST and the 256-octet DST;
  - Appendix K.6: `expand_message_xof` over SHAKE256;
  - Appendix J.9.1: G1 `hash_to_curve`;
  - an `encode` through an expander the caller implements.
  
  The values come from the plain-text RFC, in
  `tests/fixtures/rfc9380-appendix-j9.1-k1-k2-k6.json`.
- The crate's own tests still carry Appendix J.9.1, J.9.2, J.10.1 and J.10.2
  for G1 and G2.
- The exceptional cases have tests of their own, each failing with its fix
  reverted: G1 at `u = 0` and `u = ±sqrt(-1 / 11)`, G2 at `u = 0`, each onto
  `x' = B' / (Z * A')` on the isogenous curve and onto the curve itself;
  each isogeny map at a root of its `x_den`, which gives the identity, and
  beside it, which does not; and G1's whole map at a `u` the SWU map sends to
  a kernel point (11 divides the order of E1(Fp)), which gives the identity.
- `cargo tree -i crypto-bigint` shows only 0.7.x, through `elliptic-curve`
  0.14.
