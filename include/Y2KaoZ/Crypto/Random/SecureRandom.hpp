#pragma once

#include "Y2KaoZ/Crypto/Visibility.hpp"
#include "Y2KaoZ/Numeric/BigInt/BigInt.hpp"

namespace Y2KaoZ::Crypto::Random {

// Generates secure pseudo random bytes for public use
Y2KAOZCRYPTO_EXPORT auto PublicSecureRandom(const std::size_t& bytes) -> Y2KaoZ::Numeric::BigInt::BigInt;

// Generates secure pseudo random bytes that should remain private
Y2KAOZCRYPTO_EXPORT auto SecretSecureRandom(const std::size_t& bytes) -> Y2KaoZ::Numeric::BigInt::BigInt;

} // namespace Y2KaoZ::Crypto::Random