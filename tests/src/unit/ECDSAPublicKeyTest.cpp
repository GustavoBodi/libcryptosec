#include "libcryptosec/ECDSAKeyPair.h"
#include <libcryptosec/AsymmetricKey.h>
#include <libcryptosec/RSAKeyPair.h>
#include <libcryptosec/ECDSAPublicKey.h>
#include <libcryptosec/PublicKey.h>
#include <libcryptosec/ByteArray.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <sstream>
#include <gtest/gtest.h>

class ECDSAPublicKeyTest: public ::testing::Test {
  protected:
    using KeyPair = std::pair<ECDSAPublicKey, ECDSAPublicKey>;
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    KeyPair genPairPem() {
      ECDSAPublicKey first { genKeyFromPem() };
      ECDSAPublicKey second { genKeyFromPem() };
      return std::make_pair(first, second);
    }

    ECDSAPublicKey genKeyFromEvp() {
      EC_KEY *ec { EC_KEY_new() };
      EVP_PKEY *key { EVP_PKEY_new() };
      EVP_PKEY_assign_EC_KEY(key, ec);
      ECDSAPublicKey chave { key };
      return chave;
    }

    void testEvp() {
      BIO *buffer { BIO_new( BIO_s_mem() )};
      BIO_write(buffer, pem_key.c_str(), pem_key.size());

      EC_KEY *ec = EC_KEY_new();
      EVP_PKEY *key = EVP_PKEY_new();
      EVP_PKEY_assign_EC_KEY(key, ec);
      key = PEM_read_bio_PUBKEY(buffer, nullptr, nullptr, nullptr);

      ECDSAPublicKey chave { key };

      ASSERT_TRUE(chave.getEvpPkey() == key);
    }

    ECDSAPublicKey genKeyFromDer() {
      BIO *buffer;
      buffer = BIO_new(BIO_s_mem()) ;
      BIO_write(buffer, pem_key.c_str(), pem_key.size());
      EC_KEY *inter { PEM_read_bio_EC_PUBKEY(buffer, NULL, NULL, NULL) };
      EVP_PKEY *key { EVP_PKEY_new() };
      EVP_PKEY_assign_EC_KEY(key, inter);

      unsigned char *data;
      buffer = BIO_new(BIO_s_mem()) ;
      i2d_PUBKEY_bio(buffer, key);
      int ndata = BIO_get_mem_data(buffer, &data) ;
      ByteArray ret (data, ndata);

      ECDSAPublicKey chave ( ret );
      return chave;
    }

    ECDSAPublicKey genKeyFromPem() {
      ECDSAPublicKey chave ( pem_key );
      return chave;
    }

    void testKeyFromDer(ECDSAPublicKey passed_key) {
      BIO *buffer;
      buffer = BIO_new(BIO_s_mem());
      BIO_write(buffer, pem_key.c_str(), pem_key.size());
      EC_KEY *key { PEM_read_bio_EC_PUBKEY(buffer, NULL, NULL, NULL) };

      unsigned char *data;
      buffer = BIO_new(BIO_s_mem());
      i2d_EC_PUBKEY_bio(buffer, key);
      int ndata = BIO_get_mem_data(buffer, &data);
      ByteArray key_from_evp (data, ndata);
      ASSERT_TRUE(passed_key.getDerEncoded() == key_from_evp);
    }

    void testKeyFromPem(ECDSAPublicKey key) {
      std::string key_pem { key.getPemEncoded() };
      ASSERT_TRUE(key_pem == pem_key); 
    }

    void testSizeBits(ECDSAPublicKey key) {
      ASSERT_EQ(key.getSizeBits(), size);
    }

    void testSizeBytes(ECDSAPublicKey key) {
      ASSERT_EQ(key.getSize(), 72);
    }

    void testEquals() {
      ECDSAPublicKey chave ( pem_key );
      ECDSAPublicKey chave2 ( pem_key );
      ASSERT_EQ(chave.getPemEncoded(), chave2.getPemEncoded());
    }

    static int size;
    static std::string pem_key;
    static std::string der_key;
};

int ECDSAPublicKeyTest::size {256};

std::string ECDSAPublicKeyTest::pem_key {"-----BEGIN PUBLIC KEY-----\n" \
"MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEwPwx5huOBpxC0BqzWGqshXsFCcyaVP/Z\n" \
"k+blIKSUjMd6uCHc22IRfGVTXZy8BCe00HWshOIaBTT4dq5rL2tRSQ==\n" \
"-----END PUBLIC KEY-----\n" };

TEST_F(ECDSAPublicKeyTest, GenKeyFromEvp) {
  genKeyFromEvp();
}

TEST_F(ECDSAPublicKeyTest, GenKeyFromPem) {
  genKeyFromPem();
}

TEST_F(ECDSAPublicKeyTest, GenKeyFromDer) {
  genKeyFromDer();
}

TEST_F(ECDSAPublicKeyTest, TestKeyPem) {
  testKeyFromPem( genKeyFromPem() );
}

TEST_F(ECDSAPublicKeyTest, TestKeyDer) {
  testKeyFromDer( genKeyFromDer() );
}

TEST_F(ECDSAPublicKeyTest, SizeTestBitsEq) {
  testSizeBits( genKeyFromPem() );
}

TEST_F(ECDSAPublicKeyTest, SizeTestBytesEq) {
  testSizeBytes( genKeyFromPem() );
}

TEST_F(ECDSAPublicKeyTest, EqualsTest) {
  testEquals();
}

TEST_F(ECDSAPublicKeyTest, EvpTest) {
  testEvp();
}

