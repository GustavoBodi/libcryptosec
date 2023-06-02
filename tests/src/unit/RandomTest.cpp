#include "libcryptosec/Random.h"

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <sstream>
#include <gtest/gtest.h>

class RandomTest: public ::testing::Test {
  protected:
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    ByteArray genBytes() {
      return Random::bytes(length);
    }

    void checkBytes() {
      ASSERT_TRUE(genBytes() != ByteArray(0));
      ASSERT_TRUE(genBytes().size() >= 1);
    }

    // TODO
    //void randomTest(ByteArray seed) {
    //  seedData(seed);
    //  ByteArray a = genBytes();
    //  seedData(seed);
    //  ByteArray b = genBytes();
    //  ASSERT_EQ(a, b);
    //}

    ByteArray genPseudo() {
      return Random::pseudoBytes(length);
    }

    void seedData(ByteArray bytes) {
      Random::seedData(bytes);
    }

    void cleanSeed() {
      Random::cleanSeed();
    }

    void cleanSeedSanityTest() {
      ByteArray a = genBytes();
      cleanSeed();
      ByteArray b = genBytes();
      ASSERT_TRUE( a != b );
    }

    void randomStatus() {
      ASSERT_TRUE(Random::status());
    }

    static int length;
};

int RandomTest::length = 10;

TEST_F(RandomTest, SeedDataTest) {
  seedData(ByteArray("Testando aqui"));
}

TEST_F(RandomTest, GenBytesTest) {
  genBytes();
}

TEST_F(RandomTest, CheckBytesTest) {
  genBytes();
}

TEST_F(RandomTest, GenPseudoBytesTest) {
  genPseudo();
}


TEST_F(RandomTest, CleanSeedTest) {
  cleanSeedSanityTest();
}

TEST_F(RandomTest, RandomStatusTest) {
  randomStatus();
}
