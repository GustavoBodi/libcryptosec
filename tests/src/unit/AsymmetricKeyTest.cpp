#include <libcryptosec/AsymmetricKey.h>

#include <sstream>
#include <gtest/gtest.h>

class AsymmetricKeyTest: public ::testing::Test {
  protected:
    using KeyPair = std::pair<AsymmetricKey, AsymmetricKey>;
    virtual void SetUp() {

    }
    virtual void TearDown() {

    }
};

std::string someKey = "";

TEST_F(AsymmetricKeyTest, Something) {
  ASSERT_TRUE(true);
}
