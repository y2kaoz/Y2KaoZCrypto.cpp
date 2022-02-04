#pragma once

#include "Y2KaoZ/Crypto/Visibility.hpp"
#include "Y2KaoZ/Numeric/BigInt/BigInt.hpp"

namespace Y2KaoZ::Crypto::Random {

class Y2KAOZCRYPTO_EXPORT SecureRandom {
public:
  using BigInt = Y2KaoZ::Numeric::BigInt::BigInt;

  // Generates secure pseudo random bytes for public use
  static auto generatePublic(const std::size_t& bytes) -> BigInt;

  // Generates secure pseudo random bytes that should remain private
  static auto generateSecret(const std::size_t& bytes) -> BigInt;
};

} // namespace Y2KaoZ::Crypto::Random