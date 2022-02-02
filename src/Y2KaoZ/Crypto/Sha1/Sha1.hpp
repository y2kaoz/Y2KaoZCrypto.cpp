#pragma once

#include <memory>
#include <openssl/evp.h>
#include <span>
#include <vector>

namespace Y2KaoZ::Crypto::Sha1 {

class Sha1 {
public:
  static const std::size_t CHECKSUM_SIZE = 20;
  auto update(const std::byte* message, std::size_t length) -> Sha1&;
  auto update(const char* message) -> Sha1&;
  auto finalize() -> std::vector<std::byte>;

  // TODO(y2kaoz): use a concept for ContainerT
  template <class ContainerT>
  auto update(const ContainerT& message) -> Sha1& {
    const auto bytes = std::as_bytes(std::span{std::begin(message), std::end(message)});
    return update(bytes.data(), bytes.size());
  }

private:
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> mdctx{nullptr, EVP_MD_CTX_free};
};

} // namespace Y2KaoZ::Crypto::Sha1