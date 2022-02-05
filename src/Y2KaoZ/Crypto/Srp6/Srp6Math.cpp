#include "Y2KaoZ/Crypto/Srp6/Srp6Math.hpp"
#include "Y2KaoZ/Crypto/Sha1/Sha1.hpp"
#include "Y2KaoZ/Numeric/BigInt/BigInt.hpp"

namespace {

using BigInt = Y2KaoZ::Crypto::Srp6::Srp6Math::BigInt;
using Y2KaoZ::Crypto::Sha1::Sha1;
using Y2KaoZ::Numeric::BigInt::byteBuffer;
using Y2KaoZ::Numeric::BigInt::fromBuffer;

/**
 * Calculates (H(N) xor H(g))
 */
auto calcGNxor(const BigInt& N, const BigInt& g) -> BigInt {
  Sha1 sha1;
  BigInt hashedN = fromBuffer(sha1.update(byteBuffer(N)).finalize());
  BigInt hashedG = fromBuffer(sha1.update(byteBuffer(g)).finalize());
  return (hashedN ^ hashedG);
}

/**
 * Calculates the Multiplier Parameter (k)
 */
inline auto calcMultiplierParameter(bool usesSRP6a, const BigInt& N, const BigInt& g) -> BigInt {
  // in SRP-6 is (k) = 3 while in SRP-6a is (k) = H(N,g)
  return (!usesSRP6a) ? 3 : fromBuffer(Sha1{}.update(byteBuffer(N)).update(byteBuffer(g)).finalize());
}

} // namespace

namespace Y2KaoZ::Crypto::Srp6 {

using Y2KaoZ::Crypto::Sha1::Sha1;
using Y2KaoZ::Numeric::BigInt::byteBuffer;
using Y2KaoZ::Numeric::BigInt::fromBuffer;
using Y2KaoZ::Numeric::BigInt::powm;

Srp6Math::Srp6Math(BigInt safePrime, BigInt generatorModulo, bool usesSRP6a)
  : safePrime_(std::move(safePrime))
  , generatorModulo_(std::move(generatorModulo))
  , multiplierParameter_(calcMultiplierParameter(usesSRP6a, safePrime_, generatorModulo_))
  , gNxor_(calcGNxor(safePrime_, generatorModulo_)) {
}

auto Srp6Math::safePrime() const noexcept -> const BigInt& {
  return safePrime_;
}
auto Srp6Math::generatorModulo() const noexcept -> const BigInt& {
  return generatorModulo_;
}
auto Srp6Math::multiplierParameter() const noexcept -> const BigInt& {
  return multiplierParameter_;
}
auto Srp6Math::gNxor() const noexcept -> const BigInt& {
  return gNxor_;
}

auto Srp6Math::calcPrivateKey(const BigInt& salt, const std::string& username, const std::string& password) const
  -> BigInt {
  // x = hash(salt || hash(username || ":" || password))
  Sha1 sha1;
  auto innerBytes = sha1.update(username).update(":").update(password).finalize();
  auto outerBytes = sha1.update(byteBuffer(salt)).update(innerBytes).finalize();
  return fromBuffer(outerBytes);
}

auto Srp6Math::calcPasswordVerifier(const BigInt& privateKey) const -> BigInt {
  return powm(generatorModulo_, privateKey, safePrime_);
}

auto Srp6Math::validatePublicEphemeralValue(const BigInt& publicEphemeralValue) const -> bool {
  return (publicEphemeralValue % safePrime_ != 0);
}

auto Srp6Math::calcPublicEphemeralValueA(const BigInt& secretEphemeralValueA) const -> BigInt {
  auto A = powm(generatorModulo_, secretEphemeralValueA, safePrime_);
  if (!validatePublicEphemeralValue(A)) {
    throw std::runtime_error("Invalid Public Ephemeral Value A");
  }
  return A;
}

auto Srp6Math::calcPublicEphemeralValueB(const BigInt& passwordVerifier, const BigInt& secretEphemeralValueB) const
  -> BigInt {
  auto gbN = powm(generatorModulo_, secretEphemeralValueB, safePrime_);
  auto B = (multiplierParameter_ * passwordVerifier + gbN) % safePrime_;
  if (!validatePublicEphemeralValue(B)) {
    throw std::runtime_error("Invalid Public Ephemeral Value B");
  }
  return B;
}

auto Srp6Math::calcRandomScramblingParameter(const BigInt& publicEphemeralValueA, const BigInt& publicEphemeralValueB)
  const -> BigInt {
  return fromBuffer(
    Sha1{}.update(byteBuffer(publicEphemeralValueA)).update(byteBuffer(publicEphemeralValueB)).finalize());
}

auto Srp6Math::calcClientSessionKey(
  const BigInt& publicEphemeralValueB,
  const BigInt& privateKey,
  const BigInt& secretEphemeralValueA,
  const BigInt& randomScramblingParameter) const -> BigInt {
  const BigInt base = publicEphemeralValueB - multiplierParameter_ * powm(generatorModulo_, privateKey, safePrime_);
  const BigInt exponent = secretEphemeralValueA + randomScramblingParameter * privateKey;
  return powm(base, exponent, safePrime_);
}

auto Srp6Math::calcServerSessionKey(
  const BigInt& publicEphemeralValueA,
  const BigInt& passwordVerifier,
  const BigInt& randomScramblingParameter,
  const BigInt& secretEphemeralValueB) const -> BigInt {
  // S = (Av^u) ^ b
  const BigInt base = publicEphemeralValueA * powm(passwordVerifier, randomScramblingParameter, safePrime_);
  return powm(base, secretEphemeralValueB, safePrime_);
}

auto Srp6Math::calcHashedKey(const BigInt& sessionKey) const -> BigInt {
  return fromBuffer(Sha1{}.update(byteBuffer(sessionKey)).finalize());
}

auto Srp6Math::calcInterleavedKey(const BigInt& serverSessionKey) const -> BigInt {
  auto bytesSessionKey = byteBuffer(serverSessionKey);
  constexpr auto requiredLength = 32U;
  if (bytesSessionKey.size() != requiredLength) {
    throw std::invalid_argument("Session Key is not 32 bytes");
  }

  // split S into two buffers
  std::vector<std::byte> even;
  std::vector<std::byte> odd;
  even.reserve(bytesSessionKey.size() / 2);
  odd.reserve(bytesSessionKey.size() / 2);
  for (std::size_t i = 0; i < bytesSessionKey.size() / 2; ++i) {
    even.emplace_back(bytesSessionKey[2 * i]);
    odd.emplace_back(bytesSessionKey[2 * i + 1]);
  }
  assert(even.size() == bytesSessionKey.size() / 2); // NOLINT
  assert(odd.size() == bytesSessionKey.size() / 2); // NOLINT

  // find position of first nonzero byte
  size_t p = 0;
  while (p < bytesSessionKey.size() && bytesSessionKey[p] == std::byte(0)) {
    ++p;
  }
  if ((p & 1U) != 0) {
    ++p;
  } // skip one extra byte if p is odd
  p /= 2; // offset into buffers

  // hash each of the halves, starting at the first nonzero byte
  Sha1 sha1;
  auto evenHash = sha1.update(std::span(even.data(), p).data(), bytesSessionKey.size() / 2 - p).finalize();
  auto oddHash = sha1.update(std::span(odd.data(), p).data(), bytesSessionKey.size() / 2 - p).finalize();

  // stick the two hashes back together
  std::vector<std::byte> key;
  key.reserve(evenHash.size() + oddHash.size());
  for (size_t i = 0; i < evenHash.size(); ++i) {
    key.emplace_back(evenHash[i]);
    key.emplace_back(oddHash[i]);
  }
  return fromBuffer(key);
}

auto Srp6Math::calcClientKeyMatchProof(
  const std::string& username,
  const BigInt& salt,
  const BigInt& publicEphemeralValueA,
  const BigInt& publicEphemeralValueB,
  const BigInt& key) const -> BigInt {
  // M = H(H(N) xor H(g), H(I), s, A, B, K)
  Sha1 sha1;
  auto hashedI = sha1.update(username).finalize();
  sha1.update(byteBuffer(gNxor_));
  sha1.update(hashedI);
  sha1.update(byteBuffer(salt));
  sha1.update(byteBuffer(publicEphemeralValueA));
  sha1.update(byteBuffer(publicEphemeralValueB));
  sha1.update(byteBuffer(key));
  return fromBuffer(sha1.finalize());
}

auto Srp6Math::calcServerKeyMatchProof(
  const BigInt& publicEphemeralValueA,
  const BigInt& clientKeyMatchProof,
  const BigInt& key) const -> BigInt {
  // M = H(A, M, K)
  Sha1 sha1;
  sha1.update(byteBuffer(publicEphemeralValueA));
  sha1.update(byteBuffer(clientKeyMatchProof));
  sha1.update(byteBuffer(key));
  return fromBuffer(sha1.finalize());
}

} // namespace Y2KaoZ::Crypto::Srp6
