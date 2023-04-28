#include "libcryptosec/ECDSAKeyPair.h"
#include <libcryptosec/AsymmetricKey.h>
#include <libcryptosec/RSAKeyPair.h>
#include <libcryptosec/PublicKey.h>
#include <libcryptosec/ByteArray.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <sstream>
#include <gtest/gtest.h>

class PublicKeyTest: public ::testing::Test {
  protected:
    using KeyPair = std::pair<PublicKey, PublicKey>;
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    KeyPair genPairPem() {
      PublicKey first { genKeyFromPem() };
      PublicKey second { genKeyFromPem() };
      return std::make_pair(first, second);
    }

    PublicKey genKeyFromEvp() {
	    RSA *rsa = RSA_new();
	    EVP_PKEY *key = EVP_PKEY_new();
	    EVP_PKEY_assign_RSA(key, rsa);
      PublicKey chave { key };
      return chave;
    }

    void testEvp() {
	    RSA *rsa = RSA_new();
	    EVP_PKEY *key = EVP_PKEY_new();
	    EVP_PKEY_assign_RSA(key, rsa);
      PublicKey chave { key };

      ASSERT_TRUE(chave.getEvpPkey() == key);
    }

    PublicKey genKeyFromDer() {
      BIO *buffer;
      buffer = BIO_new(BIO_s_mem());
      BIO_write(buffer, pem_key.c_str(), pem_key.size());
      EVP_PKEY *key = PEM_read_bio_PUBKEY(buffer, NULL, NULL, NULL);

      unsigned char *data;
      buffer = BIO_new(BIO_s_mem());
      i2d_PUBKEY_bio(buffer, key);
      int ndata = BIO_get_mem_data(buffer, &data);
      ByteArray ret (data, ndata);

      PublicKey chave ( ret );
      return chave;
    }

    PublicKey genKeyFromPem() {
      PublicKey chave ( pem_key );
      return chave;
    }

    void testKeyFromDer(PublicKey passed_key) {
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

    void testKeyFromPem(PublicKey key) {
      std::string key_pem { key.getPemEncoded() };
      ASSERT_TRUE(key_pem == pem_key); 
    }

    void testSizeBits(PublicKey key) {
      ASSERT_EQ(key.getSizeBits(), size);
    }

    void testSizeBytes(PublicKey key) {
      ASSERT_EQ(key.getSize(), size / 8);
    }

    void testEquals() {
      PublicKey chave ( pem_key );
      PublicKey chave2 ( pem_key );
      ASSERT_EQ(chave.getPemEncoded(), chave2.getPemEncoded());
    }

    static int size;
    static std::string pem_key;
    static std::string der_key;
};

int PublicKeyTest::size {1024};

std::string PublicKeyTest::pem_key { "-----BEGIN PUBLIC KEY-----\n" \
"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/eOMLzThavagds9Z7pRZDuHFp\n" \
"f0c2x5tkOY1sOsVACNDwlpveIm+23i9/HxMXXMKddUlQ8ALwU7VKmfrekr3QBHY3\n" \
"ARr8uuvdSlmAexrgAJ3JDgRhVJOQfq9PT2yc32JHzPjIxfnNHJp5VRZjnHVFWPGF\n" \
"ED+7ZnuJy4p63c6LkwIDAQAB\n" \
"-----END PUBLIC KEY-----\n"};

TEST_F(PublicKeyTest, GenKeyFromEvp) {
  genKeyFromEvp();
}

TEST_F(PublicKeyTest, GenKeyFromPem) {
  genKeyFromPem();
}

TEST_F(PublicKeyTest, GenKeyFromDer) {
  genKeyFromDer();
}

TEST_F(PublicKeyTest, TestKeyPem) {
  testKeyFromPem( genKeyFromPem() );
}

TEST_F(PublicKeyTest, TestKeyDer) {
  testKeyFromDer( genKeyFromDer() );
}

TEST_F(PublicKeyTest, SizeTestBitsEq) {
  testSizeBits( genKeyFromPem() );
}

TEST_F(PublicKeyTest, SizeTestBytesEq) {
  testSizeBytes( genKeyFromPem() );
}

TEST_F(PublicKeyTest, EqualsTest) {
  testEquals();
}

TEST_F(PublicKeyTest, EvpTest) {
  testEvp();
}

