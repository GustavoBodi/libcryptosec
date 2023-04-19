#include <libcryptosec/Base64.h>

#include <sstream>
#include <gtest/gtest.h>


/**
 * @brief Testes unitários da classe Base64.
 */
class Base64Test : public ::testing::Test {

protected:
    using BaPair = std::pair<ByteArray, ByteArray>;
    virtual void SetUp() {
    }

    virtual void TearDown() {
    }

    BaPair BaPairFromByteArray() {
      ByteArray ba { Base64::decode(Base64Test::stringB64) };
      ByteArray copy { ba };
      return make_pair(ba, copy);
    }

    void SanityPairTest(BaPair pair) {
      ASSERT_EQ(pair.first, pair.second);
    }

    void ToStringAsciiTest(BaPair pair) {
      ASSERT_EQ(pair.first.toString(), Base64Test::stringASCII);
    }

    void ToHexTest(BaPair pair) {
      ASSERT_EQ(pair.first.toHex(), Base64Test::stringHex);
    }

    void SizeTest(BaPair pair) {
      ASSERT_EQ(pair.first.size(), pair.second.size());
    }

    void EqualsOperatorTest(BaPair pair) {
      ASSERT_TRUE(pair.first == pair.second);
    }

    void UnequalsOperatorTest(BaPair pair) {
      ASSERT_FALSE(pair.first != pair.second);
    }

    void StringStreamTest(BaPair pair) {
      std::istringstream *iss { pair.first.toStream() };
      std::string issValue { iss->str()};
      char at { pair.first.at(10) };
      ASSERT_EQ(at, compChar);
      ASSERT_EQ(issValue, stringASCII);
    }

    void EncodingSanityTest() {
      ByteArray ba { Base64::decode(Base64Test::stringB64) };
      std::string encode { Base64::encode(ba) };
      ASSERT_EQ(encode, Base64Test::stringB64);
    }

    static std::string stringASCII;
    static std::string stringHex;
    static std::string stringB64;
    static std::istringstream isstreamB64;
    static const char compChar;
    static unsigned int size;

};

/*
 * Initialization of variables used in the tests
 */
std::string Base64Test::stringASCII {"Still waiting for Silksong release..." };
std::string Base64Test::stringHex { "5374696C6C2077616974696E6720666F722053696C6B736F6E672072656C656173652E2E2E" };
std::string Base64Test::stringB64 { "U3RpbGwgd2FpdGluZyBmb3IgU2lsa3NvbmcgcmVsZWFzZS4uLg==" };
constexpr char Base64Test::compChar { 'i' };
unsigned int Base64Test::size { 37 };

TEST_F(Base64Test, SanityPair) {
  BaPair pair { BaPairFromByteArray() };
  SanityPairTest(pair);
}

TEST_F(Base64Test, ToString) {
  BaPair pair { BaPairFromByteArray() };
  ToStringAsciiTest(pair);
}

TEST_F(Base64Test, ToHexTest) {
  BaPair pair { BaPairFromByteArray() };
  ToHexTest(pair);
}

TEST_F(Base64Test, SizeTest) {
  BaPair pair { BaPairFromByteArray() };
  SizeTest(pair);
}

TEST_F(Base64Test, FromByteArray) {
  BaPair pair { BaPairFromByteArray() };
  EqualsOperatorTest(pair);
}

TEST_F(Base64Test, UnequalsOperator) {
  BaPair pair { BaPairFromByteArray() };
  UnequalsOperatorTest(pair);
}

TEST_F(Base64Test, StringStream) {
  BaPair pair { BaPairFromByteArray() };
  StringStreamTest(pair);
}

TEST_F(Base64Test, Encoding) {
  EncodingSanityTest();
}

