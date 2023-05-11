#include "libcryptosec/exception/AsymmetricCipherException.h"
#include "libcryptosec/exception/BigIntegerException.h"
#include <libcryptosec/exception/LibCryptoSecException.h>
#include <sstream>
#include <gtest/gtest.h>

class BigIntegerExceptionTest : public ::testing::Test {
  public:
  std::string throwUnknown() {
    auto unknown { BigIntegerException(BigIntegerException::UNKNOWN, "here")};
    return unknown.getMessage();
  }

  std::string throwMemory() {
    auto memory_alloc { BigIntegerException(BigIntegerException::MEMORY_ALLOC, "here") };
    return memory_alloc.getMessage();
  }

  std::string throwInternal() {
    auto internal { BigIntegerException(BigIntegerException::INTERNAL_ERROR, "here") };
    return internal.getMessage();
  }

  std::string throwUnsignedLong() {
    auto unsigned_long { BigIntegerException(BigIntegerException::UNSIGNED_LONG_OVERFLOW, "here") };
    return unsigned_long.getMessage();
  }

  std::string throwDivision() {
    auto unavailable { BigIntegerException(BigIntegerException::DIVISION_BY_ZERO, "here") };
    return unavailable.getMessage();
  }

  protected:
  static std::string where;
};

std::string BigIntegerExceptionTest::where {"here"};

TEST_F(BigIntegerExceptionTest, ThrowUnknownTest) {
  auto result = throwUnknown();
  ASSERT_EQ(result, "Unknown error");
}

TEST_F(BigIntegerExceptionTest, ThrowMemoryTest) {
  auto result = throwMemory();
  ASSERT_EQ(result, "Memory allocation error");
}

TEST_F(BigIntegerExceptionTest, ThrowInternalTest) {
  auto result = throwInternal();
  ASSERT_EQ(result, "OpenSSL BIGNUM operation internal error");
}

TEST_F(BigIntegerExceptionTest, ThrowUnsignedLongTest) {
  auto result = throwUnsignedLong();
  ASSERT_EQ(result, "Big Integer can not be represented as unsigned long");
}

TEST_F(BigIntegerExceptionTest, ThrowDivisionTest) {
  auto result = throwDivision();
  ASSERT_EQ(result, "Division by zero");
}

