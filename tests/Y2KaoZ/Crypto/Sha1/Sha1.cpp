#include "Y2KaoZ/Crypto/Sha1/Sha1.hpp"
#include "catch2/catch_all.hpp"
#include <catch2/catch_test_macros.hpp>

TEST_CASE("Sha1 Empty Input") { // NOLINT
  const std::vector<std::byte> emptyHash{std::byte(0xda), std::byte(0x39), std::byte(0xa3), std::byte(0xee),
                                         std::byte(0x5e), std::byte(0x6b), std::byte(0x4b), std::byte(0x0d),
                                         std::byte(0x32), std::byte(0x55), std::byte(0xbf), std::byte(0xef),
                                         std::byte(0x95), std::byte(0x60), std::byte(0x18), std::byte(0x90),
                                         std::byte(0xaf), std::byte(0xd8), std::byte(0x07), std::byte(0x09)};
  Y2KaoZ::Crypto::Sha1::Sha1 sha1;
  CHECK(sha1.finalize() == emptyHash);
}

TEST_CASE("Sha1 Non Empty Input") { // NOLINT
  // echo -n "USERNAME:PASSWORD" | sha1sum
  const std::vector<std::byte> nonEmptyHash{std::byte(0x5b), std::byte(0x03), std::byte(0x9d), std::byte(0x15),
                                            std::byte(0x27), std::byte(0x22), std::byte(0xe3), std::byte(0x51),
                                            std::byte(0xc8), std::byte(0xbd), std::byte(0xeb), std::byte(0xcf),
                                            std::byte(0x06), std::byte(0xfd), std::byte(0x8c), std::byte(0xd4),
                                            std::byte(0xe5), std::byte(0x24), std::byte(0x4d), std::byte(0x78)};
  const std::string username{"USERNAME"};
  const std::string password{"PASSWORD"};

  Y2KaoZ::Crypto::Sha1::Sha1 sha1;
  CHECK(sha1.update(username).update(":").update(password).finalize() == nonEmptyHash);
}