/**
 * @file se05x_crypto_p256.ipp
 * @brief NIST P-256 of the reference crypto port: key generation, ECDH (SP 800-56A, the shared
 * secret is the x coordinate), ECDSA with deterministic nonces (FIPS 186-5, RFC 6979), included by
 * `se05x_crypto.hpp`.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Field and scalar arithmetic: eight 32-bit limbs, Montgomery multiplication (CIOS), with the
 * Montgomery constants computed at compile time from the modulus. Points: projective coordinates
 * and the complete addition formula for a = -3 of Renes, Costello and Batina (2016, Algorithm 4),
 * which also doubles, so the scalar multiplication is a Montgomery ladder with a masked swap and no
 * branch on a secret bit. A peer point is checked to lie on the curve before use, and a result at
 * infinity is refused. Curve constants: FIPS 186-5 / SP 800-186 section 3.2.1.3. Bring-up code
 * (S-15): not hardened against power or fault attacks.
 */
#ifndef SE05X_CRYPTO_P256_IPP
#define SE05X_CRYPTO_P256_IPP

namespace se05x::refcrypto {

namespace p256_detail {

/// A 256-bit number, least significant limb first.
using Limbs = std::array<uint32_t, 8>;

/// A modulus and its Montgomery constants.
struct Modulus {
  Limbs m{};      ///< The modulus.
  uint32_t inv{}; ///< -m^-1 mod 2^32.
  Limbs r2{};     ///< R^2 mod m, R = 2^256.
  Limbs one{};    ///< R mod m: one in Montgomery form.
};

/// r = a + b; returns the carry.
constexpr uint32_t AddLimbs(Limbs& r, const Limbs& a, const Limbs& b) noexcept {
  uint64_t carry = 0U;
  for (std::size_t i = 0U; i < 8U; ++i) {
    const uint64_t s = static_cast<uint64_t>(a[i]) + static_cast<uint64_t>(b[i]) + carry;
    r[i] = static_cast<uint32_t>(s & 0xFFFFFFFFU);
    carry = s >> 32U;
  }
  return static_cast<uint32_t>(carry);
}

/// r = a - b; returns the borrow.
constexpr uint32_t SubLimbs(Limbs& r, const Limbs& a, const Limbs& b) noexcept {
  uint64_t borrow = 0U;
  for (std::size_t i = 0U; i < 8U; ++i) {
    const uint64_t d = (static_cast<uint64_t>(a[i]) - static_cast<uint64_t>(b[i])) - borrow;
    r[i] = static_cast<uint32_t>(d & 0xFFFFFFFFU);
    borrow = (d >> 63U) & 1U;
  }
  return static_cast<uint32_t>(borrow);
}

/// r = pick ? b : a, without a branch; `pick` is 0 or 1.
constexpr void Select(Limbs& r, const Limbs& a, const Limbs& b, uint32_t pick) noexcept {
  const uint32_t mask = 0U - (pick & 1U);
  for (std::size_t i = 0U; i < 8U; ++i) {
    r[i] = (a[i] & ~mask) | (b[i] & mask);
  }
}

/// (a + b) mod m for a, b below m.
constexpr Limbs ModAdd(const Limbs& a, const Limbs& b, const Limbs& m) noexcept {
  Limbs s{};
  Limbs d{};
  const uint32_t carry = AddLimbs(s, a, b);
  const uint32_t borrow = SubLimbs(d, s, m);
  Limbs r{};
  Select(r, s, d, carry | (borrow ^ 1U));
  return r;
}

/// (a - b) mod m for a, b below m.
constexpr Limbs ModSub(const Limbs& a, const Limbs& b, const Limbs& m) noexcept {
  Limbs d{};
  Limbs e{};
  const uint32_t borrow = SubLimbs(d, a, b);
  static_cast<void>(AddLimbs(e, d, m));
  Limbs r{};
  Select(r, d, e, borrow);
  return r;
}

/// Montgomery product a * b * R^-1 mod m (CIOS); a and b below m.
constexpr Limbs MontMul(const Limbs& a, const Limbs& b, const Modulus& mod) noexcept {
  std::array<uint32_t, 10> t{};
  for (std::size_t i = 0U; i < 8U; ++i) {
    uint64_t c = 0U;
    for (std::size_t j = 0U; j < 8U; ++j) {
      const uint64_t s = static_cast<uint64_t>(t[j]) +
                         (static_cast<uint64_t>(a[j]) * static_cast<uint64_t>(b[i])) + c;
      t[j] = static_cast<uint32_t>(s & 0xFFFFFFFFU);
      c = s >> 32U;
    }
    uint64_t s = static_cast<uint64_t>(t[8]) + c;
    t[8] = static_cast<uint32_t>(s & 0xFFFFFFFFU);
    t[9] = static_cast<uint32_t>(s >> 32U);
    const uint32_t q = t[0] * mod.inv;
    s = static_cast<uint64_t>(t[0]) + (static_cast<uint64_t>(q) * static_cast<uint64_t>(mod.m[0]));
    c = s >> 32U;
    for (std::size_t j = 1U; j < 8U; ++j) {
      s = static_cast<uint64_t>(t[j]) +
          (static_cast<uint64_t>(q) * static_cast<uint64_t>(mod.m[j])) + c;
      t[j - 1U] = static_cast<uint32_t>(s & 0xFFFFFFFFU);
      c = s >> 32U;
    }
    s = static_cast<uint64_t>(t[8]) + c;
    t[7] = static_cast<uint32_t>(s & 0xFFFFFFFFU);
    t[8] = t[9] + static_cast<uint32_t>(s >> 32U);
  }
  Limbs r{};
  for (std::size_t i = 0U; i < 8U; ++i) {
    r[i] = t[i];
  }
  Limbs d{};
  const uint32_t borrow = SubLimbs(d, r, mod.m);
  Limbs out{};
  Select(out, r, d, (t[8] | (borrow ^ 1U)) & 1U);
  return out;
}

/// The Montgomery constants of a modulus, at compile time.
constexpr Modulus MakeModulus(const Limbs& m) noexcept {
  Modulus mod{};
  mod.m = m;
  uint32_t x = 1U;
  for (uint32_t i = 0U; i < 5U; ++i) {
    x = x * (2U - (m[0] * x)); // Newton iteration for m^-1 mod 2^32
  }
  mod.inv = 0U - x;
  Limbs v{1U, 0U, 0U, 0U, 0U, 0U, 0U, 0U};
  for (uint32_t i = 0U; i < 512U; ++i) {
    v = ModAdd(v, v, m);
    if (i == 255U) {
      mod.one = v;
    }
  }
  mod.r2 = v;
  return mod;
}

/// The field prime p of P-256.
inline constexpr Modulus kP =
    MakeModulus(Limbs{0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0x00000000U, 0x00000000U, 0x00000000U,
                      0x00000001U, 0xFFFFFFFFU});
/// The group order n of P-256.
inline constexpr Modulus kN =
    MakeModulus(Limbs{0xFC632551U, 0xF3B9CAC2U, 0xA7179E84U, 0xBCE6FAADU, 0xFFFFFFFFU, 0xFFFFFFFFU,
                      0x00000000U, 0xFFFFFFFFU});
static_assert(kP.inv == 1U, "p = -1 mod 2^32");

/// Into Montgomery form.
constexpr Limbs ToMont(const Limbs& a, const Modulus& mod) noexcept {
  return MontMul(a, mod.r2, mod);
}
/// Out of Montgomery form.
constexpr Limbs FromMont(const Limbs& a, const Modulus& mod) noexcept {
  return MontMul(a, Limbs{1U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, mod);
}

/// The curve coefficient b, in Montgomery form.
inline constexpr Limbs kBMont = ToMont(Limbs{0x27D2604BU, 0x3BCE3C3EU, 0xCC53B0F6U, 0x651D06B0U,
                                             0x769886BCU, 0xB3EBBD55U, 0xAA3A93E7U, 0x5AC635D8U},
                                       kP);
/// The base point, x and y in Montgomery form.
inline constexpr Limbs kGxMont = ToMont(Limbs{0xD898C296U, 0xF4A13945U, 0x2DEB33A0U, 0x77037D81U,
                                              0x63A440F2U, 0xF8BCE6E5U, 0xE12C4247U, 0x6B17D1F2U},
                                        kP);
/// The base point y.
inline constexpr Limbs kGyMont = ToMont(Limbs{0x37BF51F5U, 0xCBB64068U, 0x6B315ECEU, 0x2BCE3357U,
                                              0x7C0F9E16U, 0x8EE7EB4AU, 0xFE1A7F9BU, 0x4FE342E2U},
                                        kP);

/// Wipe limbs (S-01).
inline void Wipe(Limbs& v) noexcept {
  ZeroizeWords(v);
}

/// Big-endian bytes to limbs.
constexpr Limbs FromBytes(std::span<const uint8_t, 32> in) noexcept {
  Limbs r{};
  for (std::size_t i = 0U; i < 8U; ++i) {
    const std::size_t o = 28U - (4U * i);
    r[i] = (static_cast<uint32_t>(in[o]) << 24U) | (static_cast<uint32_t>(in[o + 1U]) << 16U) |
           (static_cast<uint32_t>(in[o + 2U]) << 8U) | static_cast<uint32_t>(in[o + 3U]);
  }
  return r;
}

/// Limbs to big-endian bytes.
constexpr void ToBytes(const Limbs& a, std::span<uint8_t, 32> out) noexcept {
  for (std::size_t i = 0U; i < 8U; ++i) {
    const std::size_t o = 28U - (4U * i);
    out[o] = static_cast<uint8_t>(a[i] >> 24U);
    out[o + 1U] = static_cast<uint8_t>((a[i] >> 16U) & 0xFFU);
    out[o + 2U] = static_cast<uint8_t>((a[i] >> 8U) & 0xFFU);
    out[o + 3U] = static_cast<uint8_t>(a[i] & 0xFFU);
  }
}

/// a < m.
constexpr bool Less(const Limbs& a, const Limbs& m) noexcept {
  Limbs d{};
  return SubLimbs(d, a, m) == 1U;
}

/// a == 0, without an early exit.
constexpr bool IsZero(const Limbs& a) noexcept {
  const uint32_t acc = a[0] | a[1] | a[2] | a[3] | a[4] | a[5] | a[6] | a[7];
  return acc == 0U;
}

/// a mod m for any a below 2^256 and a modulus above 2^255 (one conditional subtraction).
constexpr Limbs ReduceOnce(const Limbs& a, const Limbs& m) noexcept {
  Limbs d{};
  const uint32_t borrow = SubLimbs(d, a, m);
  Limbs r{};
  Select(r, a, d, borrow ^ 1U);
  return r;
}

/// a^(m-2) mod m in Montgomery form (Fermat inverse); the exponent is public.
constexpr Limbs Invert(const Limbs& a, const Modulus& mod) noexcept {
  Limbs exponent{};
  static_cast<void>(SubLimbs(exponent, mod.m, Limbs{2U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}));
  Limbs r = mod.one;
  for (std::size_t i = 256U; i > 0U; --i) {
    const std::size_t bit = i - 1U;
    r = MontMul(r, r, mod);
    if (((exponent[bit / 32U] >> (bit % 32U)) & 1U) != 0U) {
      r = MontMul(r, a, mod);
    }
  }
  return r;
}

/// A projective point (X : Y : Z), coordinates in Montgomery form; Z = 0 is the point at infinity.
struct Point {
  Limbs x{}; ///< X.
  Limbs y{}; ///< Y.
  Limbs z{}; ///< Z.
};

/// The point at infinity (0 : 1 : 0).
constexpr Point Infinity() noexcept {
  return Point{Limbs{}, kP.one, Limbs{}};
}

/// Field helpers bound to p.
constexpr Limbs FMul(const Limbs& a, const Limbs& b) noexcept {
  return MontMul(a, b, kP);
}
/// a + b mod p.
constexpr Limbs FAdd(const Limbs& a, const Limbs& b) noexcept {
  return ModAdd(a, b, kP.m);
}
/// a - b mod p.
constexpr Limbs FSub(const Limbs& a, const Limbs& b) noexcept {
  return ModSub(a, b, kP.m);
}

/// The complete addition of Renes, Costello and Batina, Algorithm 4 (a = -3); P == Q and points
/// at infinity are handled by the same formula.
inline Point Add(const Point& p, const Point& q) noexcept {
  Limbs t0 = FMul(p.x, q.x);
  Limbs t1 = FMul(p.y, q.y);
  Limbs t2 = FMul(p.z, q.z);
  Limbs t3 = FMul(FAdd(p.x, p.y), FAdd(q.x, q.y));
  Limbs t4 = FAdd(t0, t1);
  t3 = FSub(t3, t4);
  t4 = FMul(FAdd(p.y, p.z), FAdd(q.y, q.z));
  Limbs x3 = FAdd(t1, t2);
  t4 = FSub(t4, x3);
  x3 = FMul(FAdd(p.x, p.z), FAdd(q.x, q.z));
  Limbs y3 = FAdd(t0, t2);
  y3 = FSub(x3, y3);
  Limbs z3 = FMul(kBMont, t2);
  x3 = FSub(y3, z3);
  z3 = FAdd(x3, x3);
  x3 = FAdd(x3, z3);
  z3 = FSub(t1, x3);
  x3 = FAdd(t1, x3);
  y3 = FMul(kBMont, y3);
  t1 = FAdd(t2, t2);
  t2 = FAdd(t1, t2);
  y3 = FSub(y3, t2);
  y3 = FSub(y3, t0);
  t1 = FAdd(y3, y3);
  y3 = FAdd(t1, y3);
  t1 = FAdd(t0, t0);
  t0 = FAdd(t1, t0);
  t0 = FSub(t0, t2);
  t1 = FMul(t4, y3);
  t2 = FMul(t0, y3);
  y3 = FMul(x3, z3);
  y3 = FAdd(y3, t2);
  x3 = FMul(t3, x3);
  x3 = FSub(x3, t1);
  z3 = FMul(t4, z3);
  t1 = FMul(t3, t0);
  z3 = FAdd(z3, t1);
  return Point{x3, y3, z3};
}

/// Swap two points when `bit` is 1, without a branch.
inline void CSwap(Point& a, Point& b, uint32_t bit) noexcept {
  const uint32_t mask = 0U - (bit & 1U);
  for (std::size_t i = 0U; i < 8U; ++i) {
    const uint32_t tx = (a.x[i] ^ b.x[i]) & mask;
    const uint32_t ty = (a.y[i] ^ b.y[i]) & mask;
    const uint32_t tz = (a.z[i] ^ b.z[i]) & mask;
    a.x[i] ^= tx;
    b.x[i] ^= tx;
    a.y[i] ^= ty;
    b.y[i] ^= ty;
    a.z[i] ^= tz;
    b.z[i] ^= tz;
  }
}

/// Wipe a point.
inline void Wipe(Point& p) noexcept {
  Wipe(p.x);
  Wipe(p.y);
  Wipe(p.z);
}

/// k * P with the Montgomery ladder: the same operations for every bit of k.
inline Point Multiply(const Limbs& k, const Point& p) noexcept {
  Point r0 = Infinity();
  Point r1 = p;
  for (std::size_t i = 256U; i > 0U; --i) {
    const std::size_t bit = i - 1U;
    const uint32_t b = (k[bit / 32U] >> (bit % 32U)) & 1U;
    CSwap(r0, r1, b);
    r1 = Add(r0, r1);
    r0 = Add(r0, r0);
    CSwap(r0, r1, b);
  }
  Wipe(r1);
  return r0;
}

/// The affine x and y (not in Montgomery form); false at infinity.
inline bool ToAffine(const Point& p, Limbs& x, Limbs& y) noexcept {
  if (IsZero(p.z)) {
    return false;
  }
  const Limbs zinv = Invert(p.z, kP);
  x = FromMont(FMul(p.x, zinv), kP);
  y = FromMont(FMul(p.y, zinv), kP);
  return true;
}

/// Decode and check an uncompressed public point: 0x04, x and y below p, on the curve.
inline bool Decode(std::span<const uint8_t, 65> in, Point& out) noexcept {
  if (in[0] != 0x04U) {
    return false;
  }
  const Limbs x = FromBytes(std::span<const uint8_t, 32>{in.subspan(1U, 32U).data(), 32U});
  const Limbs y = FromBytes(std::span<const uint8_t, 32>{in.subspan(33U, 32U).data(), 32U});
  if ((!Less(x, kP.m)) || (!Less(y, kP.m))) {
    return false;
  }
  const Limbs xm = ToMont(x, kP);
  const Limbs ym = ToMont(y, kP);
  const Limbs three_x = FAdd(FAdd(xm, xm), xm);
  const Limbs rhs = FAdd(FSub(FMul(FMul(xm, xm), xm), three_x), kBMont);
  const Limbs lhs = FMul(ym, ym);
  Limbs diff{};
  static_cast<void>(SubLimbs(diff, lhs, rhs));
  if (!IsZero(diff)) {
    return false;
  }
  out = Point{xm, ym, kP.one};
  return true;
}

/// The base point.
constexpr Point Generator() noexcept {
  return Point{kGxMont, kGyMont, kP.one};
}

/// 1 <= d < n.
constexpr bool ValidScalar(const Limbs& d) noexcept {
  return (!IsZero(d)) && Less(d, kN.m);
}

/// One HMAC-SHA-256 step of RFC 6979 3.2: out = HMAC_key(v || [sep] || [x || h]).
inline void Hmac(std::span<const uint8_t, 32> key, ByteSpan v, ByteSpan sep, ByteSpan x, ByteSpan h,
                 std::span<uint8_t, 32> out) noexcept {
  HmacSha256 mac(ByteSpan{key});
  mac.Update(v);
  mac.Update(sep);
  mac.Update(x);
  mac.Update(h);
  mac.Final(out);
}

/// s = k^-1 (z + r d) mod n and r = x(kG) mod n; false when either is zero.
inline bool SignWith(const Limbs& k, const Limbs& z, const Limbs& d, Limbs& r, Limbs& s) noexcept {
  Point rp = Multiply(k, Generator());
  Limbs x{};
  Limbs y{};
  const bool finite = ToAffine(rp, x, y);
  Wipe(rp);
  if (!finite) {
    return false;
  }
  r = ReduceOnce(x, kN.m);
  Limbs km = ToMont(k, kN);
  Limbs dm = ToMont(d, kN);
  const Limbs t = ModAdd(ToMont(z, kN), MontMul(ToMont(r, kN), dm, kN), kN.m);
  Limbs kinv = Invert(km, kN);
  s = FromMont(MontMul(kinv, t, kN), kN);
  Wipe(km);
  Wipe(dm);
  Wipe(kinv);
  return (!IsZero(r)) && (!IsZero(s));
}

} // namespace p256_detail

inline bool P256ValidPrivate(std::span<const uint8_t, 32> d) noexcept {
  p256_detail::Limbs v = p256_detail::FromBytes(d);
  const bool ok = p256_detail::ValidScalar(v);
  p256_detail::Wipe(v);
  return ok;
}

inline bool P256PublicKey(std::span<const uint8_t, 32> d, std::span<uint8_t, 65> pub) noexcept {
  using namespace p256_detail;
  Limbs k = FromBytes(d);
  if (!ValidScalar(k)) {
    Wipe(k);
    return false;
  }
  Point q = Multiply(k, Generator());
  Wipe(k);
  Limbs x{};
  Limbs y{};
  const bool ok = ToAffine(q, x, y);
  Wipe(q);
  if (!ok) {
    return false;
  }
  pub[0] = 0x04U;
  ToBytes(x, std::span<uint8_t, 32>{pub.subspan(1U, 32U).data(), 32U});
  ToBytes(y, std::span<uint8_t, 32>{pub.subspan(33U, 32U).data(), 32U});
  return true;
}

inline bool P256OnCurve(std::span<const uint8_t, 65> pub) noexcept {
  p256_detail::Point p{};
  return p256_detail::Decode(pub, p);
}

inline bool P256Ecdh(std::span<const uint8_t, 32> d, std::span<const uint8_t, 65> peer,
                     std::span<uint8_t, 32> secret) noexcept {
  using namespace p256_detail;
  Point q{};
  if (!Decode(peer, q)) {
    return false;
  }
  Limbs k = FromBytes(d);
  if (!ValidScalar(k)) {
    Wipe(k);
    return false;
  }
  Point r = Multiply(k, q);
  Wipe(k);
  Limbs x{};
  Limbs y{};
  const bool ok = ToAffine(r, x, y);
  Wipe(r);
  if (ok) {
    ToBytes(x, secret);
  }
  Wipe(x);
  Wipe(y);
  return ok;
}

inline bool P256Sign(std::span<const uint8_t, 32> d, std::span<const uint8_t, 32> digest,
                     std::span<uint8_t, 64> signature) noexcept {
  using namespace p256_detail;
  Limbs dl = FromBytes(d);
  if (!ValidScalar(dl)) {
    Wipe(dl);
    return false;
  }
  const Limbs z = ReduceOnce(FromBytes(digest), kN.m);
  std::array<uint8_t, 32> h{};
  ToBytes(z, std::span<uint8_t, 32>{h});
  std::array<uint8_t, 32> v{};
  std::array<uint8_t, 32> key{};
  v.fill(0x01U);
  const std::array<uint8_t, 1> zero{0x00U};
  const std::array<uint8_t, 1> one{0x01U};
  Hmac(key, ByteSpan{v}, ByteSpan{zero}, ByteSpan{d}, ByteSpan{h}, key);
  Hmac(key, ByteSpan{v}, ByteSpan{}, ByteSpan{}, ByteSpan{}, v);
  Hmac(key, ByteSpan{v}, ByteSpan{one}, ByteSpan{d}, ByteSpan{h}, key);
  Hmac(key, ByteSpan{v}, ByteSpan{}, ByteSpan{}, ByteSpan{}, v);
  bool done = false;
  for (uint32_t attempt = 0U; (attempt < 8U) && (!done); ++attempt) {
    Hmac(key, ByteSpan{v}, ByteSpan{}, ByteSpan{}, ByteSpan{}, v);
    Limbs k = FromBytes(std::span<const uint8_t, 32>{v});
    Limbs r{};
    Limbs s{};
    if (ValidScalar(k) && SignWith(k, z, dl, r, s)) {
      ToBytes(r, std::span<uint8_t, 32>{signature.subspan(0U, 32U).data(), 32U});
      ToBytes(s, std::span<uint8_t, 32>{signature.subspan(32U, 32U).data(), 32U});
      done = true;
    } else {
      Hmac(key, ByteSpan{v}, ByteSpan{zero}, ByteSpan{}, ByteSpan{}, key);
      Hmac(key, ByteSpan{v}, ByteSpan{}, ByteSpan{}, ByteSpan{}, v);
    }
    Wipe(k);
  }
  Wipe(dl);
  Zeroize(MutableByteSpan{v});
  Zeroize(MutableByteSpan{key});
  Zeroize(MutableByteSpan{h});
  return done;
}

inline bool P256Verify(std::span<const uint8_t, 65> pub, std::span<const uint8_t, 32> digest,
                       std::span<const uint8_t, 64> signature) noexcept {
  using namespace p256_detail;
  Point q{};
  if (!Decode(pub, q)) {
    return false;
  }
  const Limbs r = FromBytes(std::span<const uint8_t, 32>{signature.subspan(0U, 32U).data(), 32U});
  const Limbs s = FromBytes(std::span<const uint8_t, 32>{signature.subspan(32U, 32U).data(), 32U});
  if ((!ValidScalar(r)) || (!ValidScalar(s))) {
    return false;
  }
  const Limbs z = ReduceOnce(FromBytes(digest), kN.m);
  const Limbs w = Invert(ToMont(s, kN), kN);
  const Limbs u1 = FromMont(MontMul(ToMont(z, kN), w, kN), kN);
  const Limbs u2 = FromMont(MontMul(ToMont(r, kN), w, kN), kN);
  const Point sum = Add(Multiply(u1, Generator()), Multiply(u2, q));
  Limbs x{};
  Limbs y{};
  if (!ToAffine(sum, x, y)) {
    return false;
  }
  const Limbs v = ReduceOnce(x, kN.m);
  Limbs diff{};
  static_cast<void>(SubLimbs(diff, v, r));
  return IsZero(diff);
}

} // namespace se05x::refcrypto

#endif // SE05X_CRYPTO_P256_IPP
