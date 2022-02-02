#include "Y2KaoZ/Crypto/Sha1/Sha1.hpp"
#include <cassert>
#include <gsl/gsl_util>

namespace {

void ctx_init(std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>& mdctx) {
  if (!mdctx) {
    mdctx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (EVP_DigestInit_ex(mdctx.get(), EVP_sha1(), nullptr) != 1) {
      throw std::runtime_error("Unable to init sha1 context.");
    }
  }
  assert(mdctx); // NOLINT
}

void ctx_free(std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>& mdctx) {
  if (mdctx != nullptr) {
    mdctx.reset(nullptr);
  }
  assert(!mdctx); // NOLINT
}

} // namespace

namespace Y2KaoZ::Crypto::Sha1 {

auto Sha1::update(const std::byte* message, std::size_t length) -> Sha1& {
  ctx_init(mdctx);
  if (EVP_DigestUpdate(mdctx.get(), message, length) != 1) {
    throw std::runtime_error("Unable to update sha1 digest.");
  }
  return *this;
}

auto Sha1::update(const char* message) -> Sha1& {
  return update(std::string_view(message));
}

auto Sha1::finalize() -> std::vector<std::byte> {
  ctx_init(mdctx);
  auto finally = gsl::finally([&] { ctx_free(mdctx); });

  unsigned int md_len = 0;
  std::array<std::uint8_t, CHECKSUM_SIZE> uchars{};
  if (EVP_DigestFinal_ex(mdctx.get(), uchars.data(), &md_len) != 1) {
    throw std::runtime_error("Unable to finalize sha1 context.");
  }
  assert(md_len == CHECKSUM_SIZE); // NOLINT

  const auto span = std::as_bytes(std::span(std::begin(uchars), std::end(uchars)));
  return {span.begin(), span.end()};
}

} // namespace Y2KaoZ::Crypto::Sha1