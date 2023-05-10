#include "libcryptosec/ECDSAKeyPair.h"
#include <libcryptosec/AsymmetricKey.h>
#include <libcryptosec/RSAKeyPair.h>
#include <libcryptosec/RSAPublicKey.h>
#include <libcryptosec/PublicKey.h>
#include <libcryptosec/ByteArray.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <sstream>
#include <gtest/gtest.h>

class RSAPublicKeyTest: public ::testing::Test {
  protected:
    using KeyPair = std::pair<RSAPublicKey, RSAPublicKey>;
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    KeyPair genPairPem() {
      RSAPublicKey first { genKeyFromPem() };
      RSAPublicKey second { genKeyFromPem() };
      return std::make_pair(first, second);
    }

    RSAPublicKey genKeyFromEvp() {
      RSA *rsa = RSA_new();
      EVP_PKEY *key = EVP_PKEY_new();
      EVP_PKEY_assign_RSA(key, rsa);
      RSAPublicKey chave { key };
      return chave;
    }

    void testEvp() {
      BIO *buffer { BIO_new( BIO_s_mem() )};
      BIO_write(buffer, pem_key.c_str(), pem_key.size());

      RSA *rsa = RSA_new();
      EVP_PKEY *key = EVP_PKEY_new();
      EVP_PKEY_assign_RSA(key, rsa);
      key = PEM_read_bio_PUBKEY(buffer, nullptr, nullptr, nullptr);

      RSAPublicKey chave { key };

      ASSERT_TRUE(chave.getEvpPkey() == key);
    }

    RSAPublicKey genKeyFromDer() {
      BIO *buffer;
      buffer = BIO_new(BIO_s_mem());
      BIO_write(buffer, pem_key.c_str(), pem_key.size());
      EVP_PKEY *key = PEM_read_bio_PUBKEY(buffer, NULL, NULL, NULL);

      unsigned char *data;
      buffer = BIO_new(BIO_s_mem());
      i2d_PUBKEY_bio(buffer, key);
      int ndata = BIO_get_mem_data(buffer, &data);
      ByteArray ret (data, ndata);

      RSAPublicKey chave ( ret );
      return chave;
    }

    RSAPublicKey genKeyFromPem() {
      RSAPublicKey chave ( pem_key );
      return chave;
    }

    void testKeyFromDer(RSAPublicKey passed_key) {
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

    void testKeyFromPem(RSAPublicKey key) {
      std::string key_pem { key.getPemEncoded() };
      ASSERT_TRUE(key_pem == pem_key); 
    }

    void testSizeBits(RSAPublicKey key) {
      ASSERT_EQ(key.getSizeBits(), size);
    }

    void testSizeBytes(RSAPublicKey key) {
      ASSERT_EQ(key.getSize(), size / 8);
    }

    void testEquals() {
      RSAPublicKey chave ( pem_key );
      RSAPublicKey chave2 ( pem_key );
      ASSERT_EQ(chave.getPemEncoded(), chave2.getPemEncoded());
    }

    static int size;
    static std::string pem_key;
    static std::string der_key;
};

int RSAPublicKeyTest::size {1024};

std::string RSAPublicKeyTest::pem_key { "-----BEGIN PUBLIC KEY-----\n" \
"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/eOMLzThavagds9Z7pRZDuHFp\n" \
"f0c2x5tkOY1sOsVACNDwlpveIm+23i9/HxMXXMKddUlQ8ALwU7VKmfrekr3QBHY3\n" \
"ARr8uuvdSlmAexrgAJ3JDgRhVJOQfq9PT2yc32JHzPjIxfnNHJp5VRZjnHVFWPGF\n" \
"ED+7ZnuJy4p63c6LkwIDAQAB\n" \
"-----END PUBLIC KEY-----\n"};

TEST_F(RSAPublicKeyTest, GenKeyFromEvp) {
  genKeyFromEvp();
}

TEST_F(RSAPublicKeyTest, GenKeyFromPem) {
  genKeyFromPem();
}

TEST_F(RSAPublicKeyTest, GenKeyFromDer) {
  genKeyFromDer();
}

TEST_F(RSAPublicKeyTest, TestKeyPem) {
  testKeyFromPem( genKeyFromPem() );
}

TEST_F(RSAPublicKeyTest, TestKeyDer) {
  testKeyFromDer( genKeyFromDer() );
}

TEST_F(RSAPublicKeyTest, SizeTestBitsEq) {
  testSizeBits( genKeyFromPem() );
}

TEST_F(RSAPublicKeyTest, SizeTestBytesEq) {
  testSizeBytes( genKeyFromPem() );
}

TEST_F(RSAPublicKeyTest, EqualsTest) {
  testEquals();
}

TEST_F(RSAPublicKeyTest, EvpTest) {
  testEvp();
}

