#include "libcryptosec/ECDSAKeyPair.h"
#include <libcryptosec/AsymmetricKey.h>
#include <libcryptosec/RSAKeyPair.h>
#include <libcryptosec/DSAPublicKey.h>
#include <libcryptosec/PublicKey.h>
#include <libcryptosec/ByteArray.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <sstream>
#include <gtest/gtest.h>

class DSAPublicKeyTest: public ::testing::Test {
  protected:
    using KeyPair = std::pair<DSAPublicKey, DSAPublicKey>;
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    KeyPair genPairPem() {
      DSAPublicKey first { genKeyFromPem() };
      DSAPublicKey second { genKeyFromPem() };
      return std::make_pair(first, second);
    }

    DSAPublicKey genKeyFromEvp() {
      DSA *rsa = DSA_new();
      EVP_PKEY *key = EVP_PKEY_new();
      EVP_PKEY_assign_DSA(key, rsa);
      DSAPublicKey chave { key };
      return chave;
    }

    void testEvp() {
      BIO *buffer { BIO_new( BIO_s_mem() )};
      BIO_write(buffer, pem_key.c_str(), pem_key.size());

      DSA *dsa = DSA_new();
      EVP_PKEY *key = EVP_PKEY_new();
      EVP_PKEY_assign_DSA(key, dsa);
      key = PEM_read_bio_PUBKEY(buffer, nullptr, nullptr, nullptr);

      DSAPublicKey chave { key };

      ASSERT_TRUE(chave.getPemEncoded() == pem_key);
    }

    DSAPublicKey genKeyFromDer() {
      BIO *buffer;
      buffer = BIO_new(BIO_s_mem());
      BIO_write(buffer, pem_key.c_str(), pem_key.size());
      EVP_PKEY *key = PEM_read_bio_PUBKEY(buffer, NULL, NULL, NULL);

      unsigned char *data;
      buffer = BIO_new(BIO_s_mem());
      i2d_PUBKEY_bio(buffer, key);
      int ndata = BIO_get_mem_data(buffer, &data);
      ByteArray ret (data, ndata);

      DSAPublicKey chave ( ret );
      return chave;
    }

    DSAPublicKey genKeyFromPem() {
      DSAPublicKey chave ( pem_key );
      return chave;
    }

    void testKeyFromDer(DSAPublicKey passed_key) {
      BIO *buffer;
      buffer = BIO_new(BIO_s_mem());
      BIO_write(buffer, pem_key.c_str(), pem_key.size());
      EVP_PKEY *key = PEM_read_bio_PUBKEY(buffer, NULL, NULL, NULL);

      unsigned char *data;
      buffer = BIO_new(BIO_s_mem());
      i2d_PUBKEY_bio(buffer, key);
      int ndata = BIO_get_mem_data(buffer, &data);
      ByteArray key_from_evp (data, ndata);
      ASSERT_TRUE(passed_key.getDerEncoded() == key_from_evp);
    }

    void testKeyFromPem(DSAPublicKey key) {
      std::string key_pem { key.getPemEncoded() };
      ASSERT_TRUE(key_pem == pem_key); 
    }

    void testSizeBits(DSAPublicKey key) {
      ASSERT_EQ(key.getSizeBits(), size);
    }

    void testEquals() {
      DSAPublicKey chave ( pem_key );
      DSAPublicKey chave2 ( pem_key );
      ASSERT_EQ(chave.getPemEncoded(), chave2.getPemEncoded());
    }

    static int size;
    static std::string pem_key;
    static std::string der_key;
};

int DSAPublicKeyTest::size {2048};

std::string DSAPublicKeyTest::pem_key {"-----BEGIN PUBLIC KEY-----\n" \
"MIIDRjCCAjkGByqGSM44BAEwggIsAoIBAQD2ZANPQVAjdbpGpExG6fh2F4Vm63lj\n" \
"epy/EVDv27L5FrGaDmEq8HR6S8cUNHqtIBkYMJz/yaUJK+4eGnOgOzf/b3maEsGk\n" \
"4EYpyB/WDDNYgQfptjRrKL92PphgXeXoOYXzuShHkMQy/Et7ZV7dpfYj+MbYHIaO\n" \
"JFbji0Onc1wES5GlwPfKkcdMfCIMaLPfOochBb4s6gQpjTLzccfZGMlW7jPIyLVe\n" \
"7ROm66F4t0HpdHUE+hTxyyfFI0dczNnCGGqcgpYA2w97Ih73fbFz4NakGln0bJYY\n" \
"mTPCBT/XIki++0QMZAfZktJ1gLCG3mM/qwezdnG8pGD5JcnKBqFwaXwxAiEA4DJM\n" \
"KAY08S1xVxgbRQ0F1ZR4A+s9aGRqfZt+hUjc4BkCggEAXLS+ORq/UjQ8q+c7Cq4h\n" \
"Cm8EyiealxgFufsrQLa/NN9+y3KmG6x+STTxDdODxXQt/e0q7Trd3CPKnhsdcE+i\n" \
"olb5EMg3otu5dWw9iWJCVNqimxFCGec/Izip490yoCf3vuFEhfJhZ9aZBVWeZnJi\n" \
"/v4T2LjAyc9thEgEospTWpRCmTW3cYzX0oTNKdG4NySyCl2X+02tFooBqsFbOJCW\n" \
"agYcCzc9Xx4783P35sQ75my5ZNJzam9/22J9O+SqUNB5mFB47Zgz0og60pDIj8X7\n" \
"DcC3V1s0iMV47jDdDubxVzzYKEWmXWW4J+MqEecyEA/KMSJr3Djn6SEeob3CmCux\n" \
"JQOCAQUAAoIBABtHhVs7d3jZTVWYfce4snbix3n0yNQjfTL+RaJ6mAnU6C+70oSk\n" \
"1N+X6xs6dfegcKWNHVRUTWM4h31UVOUTUppD2J+zBsI1fbLcC9kasMfZeShQXFwi\n" \
"0rIfaXItXQAVJCiFQQfoTpg15TUy6wK11BBf1E9eZXSNiekwcWhr0RSXp37loTzq\n" \
"fCK8w1XxvQxZfpSH6GKkodNeOFFzDTdRSRK34ZCKitDq+jk8+ntUTz4+eepjU3U6\n" \
"NA/KVuy86DIELJA9zWaTCAAkUI3PFtnshYyb/+MXXjJKUX/OGFqWIx4Ty/bGFRw4\n" \
"/0ZGe/ncXZfFwntg9WHJeAC/Swg86R9kxYo=\n" \
"-----END PUBLIC KEY-----\n"};

TEST_F(DSAPublicKeyTest, GenKeyFromEvp) {
  genKeyFromEvp();
}

TEST_F(DSAPublicKeyTest, GenKeyFromPem) {
  genKeyFromPem();
}

TEST_F(DSAPublicKeyTest, GenKeyFromDer) {
  genKeyFromDer();
}

TEST_F(DSAPublicKeyTest, TestKeyPem) {
  testKeyFromPem( genKeyFromPem() );
}

TEST_F(DSAPublicKeyTest, TestKeyDer) {
  testKeyFromDer( genKeyFromDer() );
}

TEST_F(DSAPublicKeyTest, SizeTestBitsEq) {
  testSizeBits( genKeyFromPem() );
}

TEST_F(DSAPublicKeyTest, EqualsTest) {
  testEquals();
}

TEST_F(DSAPublicKeyTest, EvpTest) {
  testEvp();
}
