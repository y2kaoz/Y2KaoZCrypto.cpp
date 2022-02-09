#include "Y2KaoZ/Crypto/Random/SecureRandom.hpp"
#include <gsl/gsl_util>
#include <openssl/err.h>
#include <openssl/rand.h>

namespace Y2KaoZ::Crypto::Random {

auto PublicSecureRandom(const std::size_t& bytes) -> Y2KaoZ::Numeric::BigInt::BigInt {
  if (bytes > std::numeric_limits<int>::max()) {
    throw std::length_error("The random number is too big for the underlying implementation.");
  }
  std::vector<std::uint8_t> buffer(bytes);
  if (RAND_bytes(std::data(buffer), gsl::narrow_cast<int>(std::size(buffer))) != 1) {
    throw std::runtime_error("Error generating public random number: " + std::to_string(ERR_get_error()));
  }
  return Y2KaoZ::Numeric::BigInt::fromBuffer(buffer);
}

auto SecretSecureRandom(const std::size_t& bytes) -> Y2KaoZ::Numeric::BigInt::BigInt {
  if (bytes > std::numeric_limits<int>::max()) {
    throw std::length_error("The random number is too big for the underlying implementation.");
  }
  std::vector<std::uint8_t> buffer(bytes);
  if (RAND_priv_bytes(std::data(buffer), gsl::narrow_cast<int>(std::size(buffer))) != 1) {
    throw std::runtime_error("Error generating secret random number: " + std::to_string(ERR_get_error()));
  }
  return Y2KaoZ::Numeric::BigInt::fromBuffer(buffer);
}

} // namespace Y2KaoZ::Crypto::Random