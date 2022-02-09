#include "Y2KaoZ/Crypto/Srp6/Srp6.hpp"
#include "Y2KaoZ/Crypto/Sha1/Sha1.hpp"
#include "catch2/catch_all.hpp"
#include <catch2/catch_test_macros.hpp>

TEST_CASE("Srp6") { // NOLINT
  using Y2KaoZ::Crypto::Sha1::Sha1;
  using Y2KaoZ::Numeric::BigInt::BigInt;
  using Y2KaoZ::Numeric::BigInt::byteBuffer;
  using Y2KaoZ::Numeric::BigInt::fromBuffer;

  const BigInt safePrime("0x894b645e89e1535bbdad5b8b290650530801b18ebfbf5e8fab3c82872a3e9bb7");
  const BigInt generatorModulo(7);

  Y2KaoZ::Crypto::Srp6::Srp6 srp6(safePrime, generatorModulo, false);

  CHECK(srp6.safePrime() == safePrime);
  CHECK(srp6.generatorModulo() == generatorModulo);
  CHECK(srp6.multiplierParameter() == 3);

  const BigInt safePrimeHash = fromBuffer(Sha1{}.update(byteBuffer(safePrime)).finalize());
  const BigInt generatorModuloHash = fromBuffer(Sha1{}.update(byteBuffer(generatorModulo)).finalize());

  CHECK(srp6.gNxor() == (safePrimeHash ^ generatorModuloHash));

  const std::string username = "USERNAME";
  const std::string password = "PASSWORD";
  const BigInt salt("0x31576263a1c10a1d75ec06037721931117f7d013c7d8a93b29838d6e7996bdc5");
  const BigInt privateKey("0x8e13000ecb782fb239088a6e574de52f8fa3254b");

  CHECK(privateKey == calcPrivateKey(srp6, salt, username, password));

  const BigInt passwordVerifier("0xe60117ce887dcecedefb4fd6c86cbfdab7bb8b78425b5e6a0bd1562e27ed849");

  CHECK(passwordVerifier == calcPasswordVerifier(srp6, privateKey));

  const BigInt secretEphemeralValueA("0xa033340f240d3a12372c751115be447f60a7874c71d113ee9fd18fde6ad80fed");
  const BigInt publicEphemeralValueA("0x67b143bb4ff653ced1b4c6efca8a3ca7b96f9ad91ec45f74ccf90ddbbb3e4a40");

  CHECK(publicEphemeralValueA == calcPublicEphemeralValueA(srp6, secretEphemeralValueA));

  const BigInt secretEphemeralValueB("0x5a47482d1e2f0b768c72bf72d0139b888063b195c76ccbd1ec4d2ed74513e055");
  const BigInt publicEphemeralValueB("0x1a1075fda1dd58c1659b1dcc0395dbb8acebb295a1501f36087acb342d3b4a3e");

  CHECK(publicEphemeralValueB == calcPublicEphemeralValueB(srp6, passwordVerifier, secretEphemeralValueB));

  const BigInt randomScramblingParameter("0x81cbdedd03b4196a4452b95c7d01d58548b2acd4");

  CHECK(randomScramblingParameter == calcRandomScramblingParameter(srp6, publicEphemeralValueA, publicEphemeralValueB));

  const BigInt sessionKey("0x6fc506dc9dc2ab2243dea80af42d172d551354ed0015fa3b449a1ed4f122c664");

  const BigInt clientSessionKey =
    calcClientSessionKey(srp6, publicEphemeralValueB, privateKey, secretEphemeralValueA, randomScramblingParameter);

  const BigInt serverSessionKey = calcServerSessionKey(
    srp6,
    publicEphemeralValueA,
    passwordVerifier,
    randomScramblingParameter,
    secretEphemeralValueB);

  CHECK(sessionKey == clientSessionKey);
  CHECK(clientSessionKey == serverSessionKey);

  const BigInt interleavedKey("0xc167cc363120f32fcb53c4335ad52d7137b1c2648c3fc797ad358c1f37fc0197b295f31275140e93");

  CHECK(interleavedKey == calcInterleavedKey(srp6, sessionKey));

  const BigInt clientKeyMatchProof("0x7c6ea99648a990565ad1469b00881454b2ae5558");

  CHECK(
    clientKeyMatchProof ==
    calcClientKeyMatchProof(srp6, username, salt, publicEphemeralValueA, publicEphemeralValueB, interleavedKey));

  const BigInt serverKeyMatchProof("0xe06c63642214e078abf045562f44f835ebacbe91");

  CHECK(
    serverKeyMatchProof == calcServerKeyMatchProof(srp6, publicEphemeralValueA, clientKeyMatchProof, interleavedKey));
}
