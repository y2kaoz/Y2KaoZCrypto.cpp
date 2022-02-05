#pragma once

#include "Y2KaoZ/Crypto/Visibility.hpp"
#include "Y2KaoZ/Numeric/BigInt/BigInt.hpp"

namespace Y2KaoZ::Crypto::Srp6 {

class Y2KAOZCRYPTO_EXPORT Srp6Math {
public:
  using BigInt = Y2KaoZ::Numeric::BigInt::BigInt;

  /// @brief constructs a new Srp6 object
  /// @param safePrime       is a large safe prime (N = 2q+1, where q is prime)
  /// @param generatorModulo is the generator modulo for the safePrime
  /// @param usesSRP6a       if true the implementation uses SRP-6a else uses legacy SRP-6
  /// @note  Both safePrime and generatorModulo can be generated using:
  /// openssl dhparam -5 -text 255 | sed -e "s/ \|://g"
  Srp6Math(BigInt safePrime, BigInt generatorModulo, bool usesSRP6a = true);

  /// @brief gets the large safe prime (N)
  [[nodiscard]] auto safePrime() const noexcept -> const BigInt&;

  /// @brief gets the generator modulo for the safePrime (g)
  [[nodiscard]] auto generatorModulo() const noexcept -> const BigInt&;

  /// @brief gets the multiplier parameter (k)
  [[nodiscard]] auto multiplierParameter() const noexcept -> const BigInt&;

  /// @brief gets (H(N) xor H(g))
  [[nodiscard]] auto gNxor() const noexcept -> const BigInt&;

  /// @brief Calculates the client's private key (x)
  [[nodiscard]] auto calcPrivateKey(const BigInt& salt, const std::string& username, const std::string& password) const
    -> BigInt;

  /// @brief Calculates the client's password verifier (v)
  [[nodiscard]] auto calcPasswordVerifier(const BigInt& privateKey) const -> BigInt;

  /// @brief tests if a Public Ephemeral Value module N is not zero.
  [[nodiscard]] auto validatePublicEphemeralValue(const BigInt& publicEphemeralValue) const -> bool;

  /// @brief Calculates the client's Public Ephemeral Value (A)
  [[nodiscard]] auto calcPublicEphemeralValueA(const BigInt& secretEphemeralValueA) const -> BigInt;

  ///@brief Calculates the server's Public Ephemeral Value (B)
  [[nodiscard]] auto calcPublicEphemeralValueB(const BigInt& passwordVerifier, const BigInt& secretEphemeralValueB)
    const -> BigInt;

  ///@brief Calculates the Random Scrambling Parameter (u)
  [[nodiscard]] auto calcRandomScramblingParameter(
    const BigInt& publicEphemeralValueA,
    const BigInt& publicEphemeralValueB) const -> BigInt;

  /// @brief Calculates the client's session key (S)
  [[nodiscard]] auto calcClientSessionKey(
    const BigInt& publicEphemeralValueB,
    const BigInt& privateKey,
    const BigInt& secretEphemeralValueA,
    const BigInt& randomScramblingParameter) const -> BigInt;

  /// @brief Calculates the server session key (S)
  [[nodiscard]] auto calcServerSessionKey(
    const BigInt& publicEphemeralValueA,
    const BigInt& passwordVerifier,
    const BigInt& randomScramblingParameter,
    const BigInt& secretEphemeralValueB) const -> BigInt;

  /// @brief Calculates a key (K) from a session key (S)
  [[nodiscard]] auto calcHashedKey(const BigInt& sessionKey) const -> BigInt;
  [[nodiscard]] auto calcInterleavedKey(const BigInt& sessionKey) const -> BigInt;

  /// @brief Calculates the client's key proof (M)
  [[nodiscard]] auto calcClientKeyMatchProof(
    const std::string& username,
    const BigInt& salt,
    const BigInt& publicEphemeralValueA,
    const BigInt& publicEphemeralValueB,
    const BigInt& key) const -> BigInt;

  /// @brief Calculates the server's key proof (M)
  [[nodiscard]] auto calcServerKeyMatchProof(
    const BigInt& publicEphemeralValueA,
    const BigInt& clientKeyMatchProof,
    const BigInt& key) const -> BigInt;

private:
  BigInt safePrime_; // (N)
  BigInt generatorModulo_; // (g)
  BigInt multiplierParameter_; // (k)
  BigInt gNxor_; // (H(N) xor H(g))
};

} // namespace Y2KaoZ::Crypto::Srp6