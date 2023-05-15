#include <libcryptosec/AsymmetricKey.h>
#include <libcryptosec/DSAKeyPair.h>
#include <libcryptosec/KeyPair.h>
#include <libcryptosec/ByteArray.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <sstream>
#include <gtest/gtest.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>

class DSAKeyPairTest: public ::testing::Test {
  protected:
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    DSAKeyPair genKeysFromPem() {
      DSAKeyPair chave (size);
      return chave;
    }

    void getAlgoTest(DSAKeyPair pair) {
      ASSERT_EQ(pair.getAlgorithm(), AsymmetricKey::DSA);
    }

    void testValidGen(DSAKeyPair pair) {
      std::string private_key { pair.getPrivateKey()->getPemEncoded() };
      BIO *bo = BIO_new( BIO_s_mem() );
      BIO_write(bo, private_key.c_str(), private_key.length());
      DSA *priv_key = DSA_new();
      PEM_read_bio_DSAPrivateKey(bo, &priv_key, nullptr, nullptr);

      // Now for the public key

      std::string public_key { pair.getPublicKey()->getPemEncoded() };
      BIO *bo_pub = BIO_new( BIO_s_mem() );
      BIO_write(bo_pub, public_key.c_str(), public_key.length());
      DSA *pub_key = DSA_new();
      PEM_read_bio_DSA_PUBKEY(bo_pub, &pub_key, nullptr, nullptr);

      const BIGNUM *n_pub = DSA_get0_g(pub_key);
      const BIGNUM *n_priv = DSA_get0_g(priv_key);

      // Checking if the generated key is valid
      
      ASSERT_TRUE( BN_cmp(n_pub, n_priv) == 0 );
    }

    void testSizeBits(DSAKeyPair keys) {
      ASSERT_EQ(keys.getPrivateKey()->getSizeBits(), size);
      ASSERT_EQ(keys.getPublicKey()->getSizeBits(), size);
    }

    void testSizeBytes(DSAKeyPair keys) {
      ASSERT_EQ(keys.getPrivateKey()->getSize(), 48);
      ASSERT_EQ(keys.getPublicKey()->getSize(), 48);
    }

    void pemSanityTest(DSAKeyPair pair) {
      std::string priv_key = pair.getPemEncoded();
      ASSERT_EQ(priv_key, pair.getPrivateKey()->getPemEncoded());
    }

    void derSanityTest(DSAKeyPair pair) {
      ByteArray priv_key = pair.getDerEncoded();
      ASSERT_EQ(priv_key, pair.getPrivateKey()->getDerEncoded());
    }

    void evpSanityTest(DSAKeyPair pair) {
      EVP_PKEY *key = pair.getEvpPkey();
      ASSERT_EQ(key, pair.getPrivateKey()->getEvpPkey());
    }

    static int size;
    static std::string pem_key;
    static std::string pem_key_pass;
    static ByteArray pass;
};

int DSAKeyPairTest::size {1024};

ByteArray DSAKeyPairTest::pass { "12345" };
std::string DSAKeyPairTest::pem_key_pass { "-----BEGIN PRIVATE KEY-----\n" \
"MIICZAIBADCCAjkGByqGSM44BAEwggIsAoIBAQCzeM3QkzfEo1eP46ODENj2X46/\n" \
"k7osSWQtj3XwuEOKRWVBqpcy7VR/VqdZAXXeOk5acLt4eKKiAIPDiM6bvav9SwSW\n" \
"a4RepI5TFTiv8gunA0r33L/kivSNeF7tqsJTN7c1QtqgLDiYwZtrElTWxDm/S7o+\n" \
"mlZEGJkTkrOF86nlHr1D8N0jbxD7nAYPls50dp0ILfpzz+szFZ8NyVz7ReaflgJR\n" \
"OG1JArLMsZ4sWpYGRK16ueF7JhjTVUoI7FUKbd+Vj0PabM92YvM/G/Jx55qDJyds\n" \
"avGJ5ByIvbEGoHBVbS+2zm8N6tKC12vL7qdw7rPe0umIscbnTLLqQkuyUZcZAiEA\n" \
"xF1QrA5W+P5JkkiuFchNRTyoz07DA6Iac5fSwZkdsQUCggEAN7IYveeMqUBKLwPW\n" \
"P4ZBxZ51FiqCS8iVkFWHhr7G0I6SD5zyQFntPjd0wSmHP7toBxLoa2ypLTOLYRip\n" \
"zrEqUIDOvkBP524vhJ6Q9uvBEvRhMToIQF6M/AdnQlod7bBqh+lIks+Uhgf6GbfK\n" \
"m+o2F0czCae332WhXY+KSGPHL/uDdSYwAIrup12FwWHmsLByboSoLPYtgeEDd8dj\n" \
"Oqku8FhhwZ1hRr9/JDtlLepSPHd2pSsgynafu6YI+UmlqaR7ftmxcqYETuqQsijp\n" \
"Mkm2v6lnvQnl9nVKkwAvjaikph6lRZTBm/v45bfGKcI2jWCFQwCGsZI9ykNiyoNz\n" \
"M+r5uwQiAiAS+RsU3FjqFFqgevVK/xSu30MN62ZkXFB5TqZ6ohoD7w==\n" \
"-----END PRIVATE KEY-----\n"};

std::string DSAKeyPairTest::pem_key {"-----BEGIN PRIVATE KEY-----\n" \
"MIICZQIBADCCAjkGByqGSM44BAEwggIsAoIBAQCzeM3QkzfEo1eP46ODENj2X46/\n" \
"k7osSWQtj3XwuEOKRWVBqpcy7VR/VqdZAXXeOk5acLt4eKKiAIPDiM6bvav9SwSW\n" \
"a4RepI5TFTiv8gunA0r33L/kivSNeF7tqsJTN7c1QtqgLDiYwZtrElTWxDm/S7o+\n" \
"mlZEGJkTkrOF86nlHr1D8N0jbxD7nAYPls50dp0ILfpzz+szFZ8NyVz7ReaflgJR\n" \
"OG1JArLMsZ4sWpYGRK16ueF7JhjTVUoI7FUKbd+Vj0PabM92YvM/G/Jx55qDJyds\n" \
"avGJ5ByIvbEGoHBVbS+2zm8N6tKC12vL7qdw7rPe0umIscbnTLLqQkuyUZcZAiEA\n" \
"xF1QrA5W+P5JkkiuFchNRTyoz07DA6Iac5fSwZkdsQUCggEAN7IYveeMqUBKLwPW\n" \
"P4ZBxZ51FiqCS8iVkFWHhr7G0I6SD5zyQFntPjd0wSmHP7toBxLoa2ypLTOLYRip\n" \
"zrEqUIDOvkBP524vhJ6Q9uvBEvRhMToIQF6M/AdnQlod7bBqh+lIks+Uhgf6GbfK\n" \
"m+o2F0czCae332WhXY+KSGPHL/uDdSYwAIrup12FwWHmsLByboSoLPYtgeEDd8dj\n" \
"Oqku8FhhwZ1hRr9/JDtlLepSPHd2pSsgynafu6YI+UmlqaR7ftmxcqYETuqQsijp\n" \
"Mkm2v6lnvQnl9nVKkwAvjaikph6lRZTBm/v45bfGKcI2jWCFQwCGsZI9ykNiyoNz\n" \
"M+r5uwQjAiEAkvZqydM5UJ/6jqn1pr5DuhoX25QSgHKyGJpfehIwqbU=\n" \
"-----END PRIVATE KEY-----\n"};

TEST_F(DSAKeyPairTest, GenKey) {
  genKeysFromPem();
}

TEST_F(DSAKeyPairTest, GeneratedKeyTest) {
  testValidGen(genKeysFromPem());
}

TEST_F(DSAKeyPairTest, AlgorithmTest) {
  getAlgoTest(genKeysFromPem());
}

TEST_F(DSAKeyPairTest, EvpSanityTest) {
  evpSanityTest( genKeysFromPem() );
}

TEST_F(DSAKeyPairTest, DerSanityTest) {
  derSanityTest( genKeysFromPem() );
}

TEST_F(DSAKeyPairTest, PemSanityTest) {
  pemSanityTest( genKeysFromPem() );
}

TEST_F(DSAKeyPairTest, SizeTestBitsEq) {
  testSizeBits( genKeysFromPem() );
}

TEST_F(DSAKeyPairTest, SizeTestBytesEq) {
  testSizeBytes( genKeysFromPem() );
}

