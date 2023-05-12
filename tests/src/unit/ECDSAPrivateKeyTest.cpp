#include "libcryptosec/ECDSAKeyPair.h"
#include <libcryptosec/AsymmetricKey.h>
#include <libcryptosec/RSAKeyPair.h>
#include <libcryptosec/ECDSAPrivateKey.h>
#include <libcryptosec/ByteArray.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>

#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <sstream>
#include <gtest/gtest.h>

class ECDSAPrivateKeyTest: public ::testing::Test {
  protected:
    using KeyPair = std::pair<ECDSAPrivateKey, ECDSAPrivateKey>;
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    KeyPair genPairPem() {
      ECDSAPrivateKey first { genKeyFromPem() };
      ECDSAPrivateKey second { genKeyFromPem() };
      return std::make_pair(first, second);
    }

    ECDSAPrivateKey genKeyFromEvp() {
      EC_KEY *ec = EC_KEY_new();
      EVP_PKEY *key = EVP_PKEY_new();
      EVP_PKEY_assign_EC_KEY(key, ec);
      ECDSAPrivateKey chave { key };
      return chave;
    }

    void testEvp() {
      BIO *buffer { BIO_new( BIO_s_mem() )};
      BIO_write(buffer, pem_key.c_str(), pem_key.size());

      EC_KEY *ec = EC_KEY_new();
      EVP_PKEY *key = EVP_PKEY_new();
      EVP_PKEY_assign_EC_KEY(key, ec);
      key = PEM_read_bio_PrivateKey(buffer, nullptr, nullptr, nullptr);

      ECDSAPrivateKey chave { key };

      ASSERT_TRUE(chave.getEvpPkey() == key);
    }

    ECDSAPrivateKey genKeyFromDer() {
      BIO *buffer;
      buffer = BIO_new(BIO_s_mem());
      BIO_write(buffer, pem_key.c_str(), pem_key.size());
      EC_KEY *inter = PEM_read_bio_ECPrivateKey(buffer, NULL, NULL, NULL);
      EVP_PKEY *key = EVP_PKEY_new();
      EVP_PKEY_assign_EC_KEY(key, inter);

      unsigned char *data;
      buffer = BIO_new(BIO_s_mem());
      i2d_PrivateKey_bio(buffer, key);
      int ndata = BIO_get_mem_data(buffer, &data);
      ByteArray ret (data, ndata);

      ECDSAPrivateKey chave ( ret );
      return chave;
    }

    ECDSAPrivateKey genKeyFromPem() {
      ECDSAPrivateKey chave ( pem_key );
      return chave;
    }

    ECDSAPrivateKey genKeyFromPemPass() {
      ECDSAPrivateKey chave (pem_key_pass, pass);
      return chave;
    }

    void testKeyFromDer(ECDSAPrivateKey passed_key) {
      BIO *buffer;
      buffer = BIO_new(BIO_s_mem());
      BIO_write(buffer, pem_key.c_str(), pem_key.size());
      EC_KEY *key = PEM_read_bio_ECPrivateKey(buffer, NULL, NULL, NULL);

      unsigned char *data;
      buffer = BIO_new(BIO_s_mem());
      i2d_ECPrivateKey_bio(buffer, key);
      int ndata = BIO_get_mem_data(buffer, &data);
      ByteArray key_from_evp (data, ndata);
      ASSERT_TRUE(passed_key.getDerEncoded() == key_from_evp);
    }

    void testKeyFromPem(ECDSAPrivateKey key) {
      std::string key_pem { key.getPemEncoded() };
      ASSERT_TRUE(key_pem == pem_key); 
    }

    void testSizeBits(ECDSAPrivateKey key) {
      ASSERT_EQ(key.getSizeBits(), size);
    }

    void testSizeBytes(ECDSAPrivateKey key) {
      ASSERT_EQ(key.getSize(), 72);
    }

    void testEquals() {
      ECDSAPrivateKey chave ( pem_key );
      ECDSAPrivateKey chave2 ( pem_key );
      ASSERT_EQ(chave.getPemEncoded(), chave2.getPemEncoded());
    }

    static int size;
    static std::string pem_key;
    static std::string pem_key_pass;
    static ByteArray pass;
};

int ECDSAPrivateKeyTest::size {256};

ByteArray ECDSAPrivateKeyTest::pass { "12345" };
std::string ECDSAPrivateKeyTest::pem_key_pass { "-----BEGIN EC PRIVATE KEY-----\n" \
"Proc-Type: 4,ENCRYPTED\n" \
"DEK-Info: AES-256-CBC,4065373A17B5C0AD827303D726753DB2\n" \
"\n" \
"Y4lsqUhsAESA5BZ6UFRD6NMqj3qs6gh7mUcIL4ofItk/Ubl9bKx1hYWTAoAUk9fm\n" \
"Zzn8IhNSBusx3pILYJpdwlXGPmz/4kKGTLk+XSwBCAH8dianCFlr1W0bp7CZWwYf\n" \
"/jcBx7tP4SEvdXR8MNJv2TBrDleC6QmMGM4i8Eir1CQ=\n" \
"-----END EC PRIVATE KEY-----\n" };

std::string ECDSAPrivateKeyTest::pem_key {"-----BEGIN PRIVATE KEY-----\n" \
"MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgJzF+xTug88/hzy2coPRh\n" \
"tA9t4XZjzWGc3eBW5PtaYAmhRANCAATA/DHmG44GnELQGrNYaqyFewUJzJpU/9mT\n" \
"5uUgpJSMx3q4IdzbYhF8ZVNdnLwEJ7TQdayE4hoFNPh2rmsva1FJ\n" \
"-----END PRIVATE KEY-----\n" };

TEST_F(ECDSAPrivateKeyTest, GenKeyFromEvp) {
  genKeyFromEvp();
}

TEST_F(ECDSAPrivateKeyTest, GenKeyFromPem) {
  genKeyFromPem();
}

TEST_F(ECDSAPrivateKeyTest, GenKeyFromPemPass) {
  genKeyFromPemPass();
}

TEST_F(ECDSAPrivateKeyTest, GenKeyFromDer) {
  genKeyFromDer();
}

TEST_F(ECDSAPrivateKeyTest, TestKeyPem) {
  testKeyFromPem( genKeyFromPem() );
}

TEST_F(ECDSAPrivateKeyTest, TestKeyDer) {
  testKeyFromDer( genKeyFromDer() );
}

TEST_F(ECDSAPrivateKeyTest, SizeTestBitsEq) {
  testSizeBits( genKeyFromPem() );
}

TEST_F(ECDSAPrivateKeyTest, SizeTestBytesEq) {
  testSizeBytes( genKeyFromPem() );
}

TEST_F(ECDSAPrivateKeyTest, EqualsTest) {
  testEquals();
}

TEST_F(ECDSAPrivateKeyTest, EvpTest) {
  testEvp();
}

