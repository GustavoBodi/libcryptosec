#include "libcryptosec/exception/AsymmetricCipherException.h"
#include <libcryptosec/exception/LibCryptoSecException.h>
#include <sstream>
#include <gtest/gtest.h>

class AsymmetricCipherExceptionTest : public ::testing::Test {
  public:
  std::string getMessage() {
    std::string message { AsymmetricCipherException("valores").getMessage() };
    return message;
  }

  std::string toString() {
    std::string toString { AsymmetricCipherException("valores").toString()};
    return toString;
  }

  std::string throwUnknown() {
    auto unknown { AsymmetricCipherException(AsymmetricCipherException::UNKNOWN, "here")};
    return unknown.getMessage();
  }

  std::string throwEncryptingData() {
    auto encrypting { AsymmetricCipherException(AsymmetricCipherException::ENCRYPTING_DATA, "here") };
    return encrypting.getMessage();
  }

  std::string throwDecryptingData() {
    auto decrypting { AsymmetricCipherException(AsymmetricCipherException::DECRYPTING_DATA, "here") };
    return decrypting.getMessage();
  }
  protected:
  static std::string where;
};

std::string AsymmetricCipherExceptionTest::where {"here"};

TEST_F(AsymmetricCipherExceptionTest, ToString) {
  auto result = toString();
  ASSERT_EQ(result, "AsymmetricCipherException. Called by: valores.");
}

TEST_F(AsymmetricCipherExceptionTest, ThrowUnknown) {
  auto result = throwUnknown();
  ASSERT_EQ(result, "Unknown error");
}

TEST_F(AsymmetricCipherExceptionTest, ThrowEncrypting) {
  auto result = throwEncryptingData();
  ASSERT_EQ(result, "Encrypting data");
}

TEST_F(AsymmetricCipherExceptionTest, ThrowDecrypting) {
  auto result = throwDecryptingData();
  ASSERT_EQ(result, "Decrypting data");
}

