#include "libcryptosec/ECDSAKeyPair.h"
#include <libcryptosec/AsymmetricKey.h>
#include <libcryptosec/RSAKeyPair.h>
#include <libcryptosec/PrivateKey.h>
#include <libcryptosec/ByteArray.h>
#include <libcryptosec/DSAPrivateKey.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <sstream>
#include <gtest/gtest.h>

class DSAPrivateKeyTest: public ::testing::Test {
  protected:
    using KeyPair = std::pair<DSAPrivateKey, DSAPrivateKey>;
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    KeyPair genPairPem() {
      DSAPrivateKey first { genKeyFromPem() };
      DSAPrivateKey second { genKeyFromPem() };
      return std::make_pair(first, second);
    }

    DSAPrivateKey genKeyFromEvp() {
      DSA *dsa = DSA_new();
      EVP_PKEY *key = EVP_PKEY_new();
      EVP_PKEY_assign_DSA(key, dsa);
      DSAPrivateKey chave { key };
      return chave;
    }

    void testEvp() {
      BIO *buffer { BIO_new( BIO_s_mem() )};
      BIO_write(buffer, pem_key.c_str(), pem_key.size());

      DSA *dsa = DSA_new();
      EVP_PKEY *key = EVP_PKEY_new();
      EVP_PKEY_assign_DSA(key, dsa);
      key = PEM_read_bio_PrivateKey(buffer, nullptr, nullptr, nullptr);
      
      DSAPrivateKey chave { key };

      ASSERT_TRUE(chave.getPemEncoded() == pem_key);
    }

    DSAPrivateKey genKeyFromDer() {
      BIO *buffer;
      buffer = BIO_new(BIO_s_mem());
      BIO_write(buffer, pem_key.c_str(), pem_key.size());
      EVP_PKEY *key = PEM_read_bio_PrivateKey(buffer, NULL, NULL, NULL);

      unsigned char *data;
      buffer = BIO_new(BIO_s_mem());
      i2d_PrivateKey_bio(buffer, key);
      int ndata = BIO_get_mem_data(buffer, &data);
      ByteArray ret (data, ndata);

      DSAPrivateKey chave ( ret );
      return chave;
    }

    DSAPrivateKey genKeyFromPem() {
      DSAPrivateKey chave ( pem_key );
      return chave;
    }

    DSAPrivateKey genKeyFromPemPass() {
      DSAPrivateKey chave (pem_key_pass, pass);
      return chave;
    }

    void testKeyFromDer(DSAPrivateKey passed_key) {
      BIO *buffer;
      buffer = BIO_new(BIO_s_mem());
      BIO_write(buffer, pem_key.c_str(), pem_key.size());
      EVP_PKEY *key = PEM_read_bio_PrivateKey(buffer, NULL, NULL, NULL);

      unsigned char *data;
      buffer = BIO_new(BIO_s_mem());
      i2d_PrivateKey_bio(buffer, key);
      int ndata = BIO_get_mem_data(buffer, &data);
      ByteArray key_from_evp (data, ndata);
      ASSERT_TRUE(passed_key.getDerEncoded() == key_from_evp);
    }

    void testKeyFromPem(DSAPrivateKey key) {
      std::string key_pem { key.getPemEncoded() };
      ASSERT_TRUE(key_pem == pem_key); 
    }

    void testSizeBits(DSAPrivateKey key) {
      ASSERT_EQ(key.getSizeBits(), size);
    }

    void testEquals() {
      DSAPrivateKey chave ( pem_key );
      DSAPrivateKey chave2 ( pem_key );
      ASSERT_EQ(chave.getPemEncoded(), chave2.getPemEncoded());
    }

    static int size;
    static std::string pem_key;
    static std::string pem_key_pass;
    static ByteArray pass;
};

int DSAPrivateKeyTest::size {2048};

ByteArray DSAPrivateKeyTest::pass { "12345" };
std::string DSAPrivateKeyTest::pem_key_pass { "-----BEGIN PRIVATE KEY-----\n" \
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

std::string DSAPrivateKeyTest::pem_key {"-----BEGIN PRIVATE KEY-----\n" \
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

TEST_F(DSAPrivateKeyTest, GenKeyFromEvp) {
  genKeyFromEvp();
}

TEST_F(DSAPrivateKeyTest, GenKeyFromPem) {
  genKeyFromPem();
}

TEST_F(DSAPrivateKeyTest, GenKeyFromPemPass) {
  genKeyFromPemPass();
}

TEST_F(DSAPrivateKeyTest, GenKeyFromDer) {
  genKeyFromDer();
}

TEST_F(DSAPrivateKeyTest, TestKeyPem) {
  testKeyFromPem( genKeyFromPem() );
}

TEST_F(DSAPrivateKeyTest, TestKeyDer) {
  testKeyFromDer( genKeyFromDer() );
}

TEST_F(DSAPrivateKeyTest, SizeTestBitsEq) {
  testSizeBits( genKeyFromPem() );
}

TEST_F(DSAPrivateKeyTest, EqualsTest) {
  testEquals();
}

TEST_F(DSAPrivateKeyTest, EvpTest) {
  testEvp();
}

