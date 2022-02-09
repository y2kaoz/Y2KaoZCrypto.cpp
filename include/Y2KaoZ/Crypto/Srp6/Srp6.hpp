#pragma once

#include "Y2KaoZ/Crypto/Visibility.hpp"
#include "Y2KaoZ/Numeric/BigInt/BigInt.hpp"

namespace Y2KaoZ::Crypto::Srp6 {

using BigInt = Y2KaoZ::Numeric::BigInt::BigInt;

class Y2KAOZCRYPTO_EXPORT Srp6 {
public:
  /// @brief constructs a new Srp6 object
  /// @param safePrime       is a large safe prime (N = 2q+1, where q is prime)
  /// @param generatorModulo is the generator modulo for the safePrime
  /// @param usesSRP6a       if true the implementation uses SRP-6a else uses legacy SRP-6
  /// @note  Both safePrime and generatorModulo can be generated using:
  /// openssl dhparam -5 -text 255 | sed -e "s/ \|://g"
  Srp6(BigInt safePrime, BigInt generatorModulo, bool usesSRP6a = true);

  /// @brief gets the large safe prime (N)
  [[nodiscard]] auto safePrime() const noexcept -> const BigInt&;

  /// @brief gets the generator modulo for the safePrime (g)
  [[nodiscard]] auto generatorModulo() const noexcept -> const BigInt&;

  /// @brief gets the multiplier parameter (k)
  [[nodiscard]] auto multiplierParameter() const noexcept -> const BigInt&;

  /// @brief gets (H(N) xor H(g))
  [[nodiscard]] auto gNxor() const noexcept -> const BigInt&;

private:
  BigInt safePrime_; // (N)
  BigInt generatorModulo_; // (g)
  BigInt multiplierParameter_; // (k)
  BigInt gNxor_; // (H(N) xor H(g))
};

/// @brief Calculates the client's private key (x)
[[nodiscard]] Y2KAOZCRYPTO_EXPORT auto calcPrivateKey(
  const Srp6& /*srp6*/,
  const BigInt& salt,
  const std::string& username,
  const std::string& password) -> BigInt;

/// @brief Calculates the client's password verifier (v)
[[nodiscard]] Y2KAOZCRYPTO_EXPORT auto calcPasswordVerifier(const Srp6& srp6, const BigInt& privateKey) -> BigInt;

/// @brief tests if a Public Ephemeral Value module N is not zero.
[[nodiscard]] Y2KAOZCRYPTO_EXPORT auto validatePublicEphemeralValue(
  const Srp6& srp6,
  const BigInt& publicEphemeralValue) -> bool;

/// @brief Calculates the client's Public Ephemeral Value (A)
[[nodiscard]] Y2KAOZCRYPTO_EXPORT auto calcPublicEphemeralValueA(const Srp6& srp6, const BigInt& secretEphemeralValueA)
  -> BigInt;

///@brief Calculates the server's Public Ephemeral Value (B)
[[nodiscard]] Y2KAOZCRYPTO_EXPORT auto calcPublicEphemeralValueB(
  const Srp6& srp6,
  const BigInt& passwordVerifier,
  const BigInt& secretEphemeralValueB) -> BigInt;

///@brief Calculates the Random Scrambling Parameter (u)
[[nodiscard]] Y2KAOZCRYPTO_EXPORT auto calcRandomScramblingParameter(
  const Srp6& /*srp6*/,
  const BigInt& publicEphemeralValueA,
  const BigInt& publicEphemeralValueB) -> BigInt;

/// @brief Calculates the client's session key (S)
[[nodiscard]] Y2KAOZCRYPTO_EXPORT auto calcClientSessionKey(
  const Srp6& srp6,
  const BigInt& publicEphemeralValueB,
  const BigInt& privateKey,
  const BigInt& secretEphemeralValueA,
  const BigInt& randomScramblingParameter) -> BigInt;

/// @brief Calculates the server session key (S)
[[nodiscard]] Y2KAOZCRYPTO_EXPORT auto calcServerSessionKey(
  const Srp6& srp6,
  const BigInt& publicEphemeralValueA,
  const BigInt& passwordVerifier,
  const BigInt& randomScramblingParameter,
  const BigInt& secretEphemeralValueB) -> BigInt;

/// @brief Calculates a key (K) from a session key (S)
[[nodiscard]] Y2KAOZCRYPTO_EXPORT auto calcHashedKey(const Srp6& /*srp6*/, const BigInt& sessionKey) -> BigInt;
[[nodiscard]] Y2KAOZCRYPTO_EXPORT auto calcInterleavedKey(const Srp6& /*srp6*/, const BigInt& sessionKey) -> BigInt;

/// @brief Calculates the client's key proof (M)
[[nodiscard]] Y2KAOZCRYPTO_EXPORT auto calcClientKeyMatchProof(
  const Srp6& srp6,
  const std::string& username,
  const BigInt& salt,
  const BigInt& publicEphemeralValueA,
  const BigInt& publicEphemeralValueB,
  const BigInt& key) -> BigInt;

/// @brief Calculates the server's key proof (M)
[[nodiscard]] Y2KAOZCRYPTO_EXPORT auto calcServerKeyMatchProof(
  const Srp6& /*srp6*/,
  const BigInt& publicEphemeralValueA,
  const BigInt& clientKeyMatchProof,
  const BigInt& key) -> BigInt;

} // namespace Y2KaoZ::Crypto::Srp6