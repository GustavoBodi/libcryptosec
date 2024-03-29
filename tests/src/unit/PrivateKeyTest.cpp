#include "libcryptosec/ECDSAKeyPair.h"
#include <libcryptosec/AsymmetricKey.h>
#include <libcryptosec/RSAKeyPair.h>
#include <libcryptosec/PrivateKey.h>
#include <libcryptosec/ByteArray.h>
#include <openssl/rsa.h>

#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <sstream>
#include <gtest/gtest.h>

class PrivateKeyTest: public ::testing::Test {
  protected:
    using KeyPair = std::pair<PrivateKey, PrivateKey>;
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    KeyPair genPairPem() {
      PrivateKey first { genKeyFromPem() };
      PrivateKey second { genKeyFromPem() };
      return std::make_pair(first, second);
    }

    PrivateKey genKeyFromEvp() {
      RSA *rsa = RSA_new();
      EVP_PKEY *key = EVP_PKEY_new();
      EVP_PKEY_assign_RSA(key, rsa);
      PrivateKey chave { key };
      return chave;
    }

    void testEvp() {
      BIO *buffer { BIO_new( BIO_s_mem() )};
      BIO_write(buffer, pem_key.c_str(), pem_key.size());

      RSA *rsa = RSA_new();
      EVP_PKEY *key = EVP_PKEY_new();
      EVP_PKEY_assign_RSA(key, rsa);
      key = PEM_read_bio_PrivateKey(buffer, nullptr, nullptr, nullptr);

      PrivateKey chave { key };

      ASSERT_TRUE(chave.getPemEncoded() == pem_key);
    }

    PrivateKey genKeyFromDer() {
      BIO *buffer;
      buffer = BIO_new(BIO_s_mem());
      BIO_write(buffer, pem_key.c_str(), pem_key.size());
      EVP_PKEY *key = PEM_read_bio_PrivateKey(buffer, NULL, NULL, NULL);

      unsigned char *data;
      buffer = BIO_new(BIO_s_mem());
      i2d_PrivateKey_bio(buffer, key);
      int ndata = BIO_get_mem_data(buffer, &data);
      ByteArray ret (data, ndata);

      PrivateKey chave ( ret );
      return chave;
    }

    PrivateKey genKeyFromPem() {
      PrivateKey chave ( pem_key );
      return chave;
    }

    PrivateKey genKeyFromPemPass() {
      PrivateKey chave (pem_key_pass, pass);
      return chave;
    }

    void testKeyFromDer(PrivateKey passed_key) {
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

    void testKeyFromPem(PrivateKey key) {
      std::string key_pem { key.getPemEncoded() };
      ASSERT_TRUE(key_pem == pem_key); 
    }

    void testSizeBits(PrivateKey key) {
      ASSERT_EQ(key.getSizeBits(), size);
    }

    void testSizeBytes(PrivateKey key) {
      ASSERT_EQ(key.getSize(), size / 8);
    }

    void testEquals() {
      PrivateKey chave ( pem_key );
      PrivateKey chave2 ( pem_key );
      ASSERT_EQ(chave.getPemEncoded(), chave2.getPemEncoded());
    }

    static int size;
    static std::string pem_key;
    static std::string pem_key_pass;
    static ByteArray pass;
};

int PrivateKeyTest::size {1024};

ByteArray PrivateKeyTest::pass { "12345" };
std::string PrivateKeyTest::pem_key_pass { "-----BEGIN PRIVATE KEY-----\n" \
"MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALXXssasDkddanEo\n" \
"5KZFdPYGss/ZdJcIcSdPhIAkskLE7EAUsJEJaBs+Lb3jnAamHMraKI1CsTo56kjG\n" \
"hC7yErLwyXCxREynctC2Qe6wWaHxcz8oCXncOnLC5T1e4mDY+h4w34UDFMt4CbnP\n" \
"Lyrkz3cNCgQQIci6HZ5aERyo9TZ9AgMBAAECgYBiexfqOuJcyf3MnS3/0pv+ZjBP\n" \
"GuDmrv7BIHKNB9K3EHk2Vz4svmBwaKNTNMKaYzoyriXKIzViaF023rRVzGpNLfBF\n" \
"kODWHa1KbJbxonPHXBMjbLp69jPLr4NgqQclEY/W2uVFAVA0jBF3cmQrhUlCoqAH\n" \
"TAYwlf99sHeijrpIjQJBAO6q6xGTnjClTwWoKOfr6F0TBZqHjW8FILyfhZMrhwo6\n" \
"9zScvIN9iwIUMiVhBq39q9139rywKDEKfXBfstlfP+cCQQDDDFekTaptsLDw6AdW\n" \
"EYTtklXBXhB0zhQqjxWM82pCHUSF9RpuK7ChbDQtbNfJAgSvq5mXO3+onYGbQohP\n" \
"jBn7AkEAnqIsLDqZ4mt94pyq07wRbgu+pb+DWk9mOvksp20/DKW0uduT0TIYuwEB\n" \
"c6bR8cOyADpEXZYYoMAAMDjrf1+38QJAWG1wDn1nlvNUROPs74hhy5NcbZ5Ht6z2\n" \
"V5UnIA/7TJ4YQuMsaGZGXejAfxepfOf9V+dkarv+1GMUL1+qjOXnoQJBAKUXBizf\n" \
"SNzTXaGBFgjBznqXlm09YeCL+ndsxTlyVyvxXt0wVym5QJ0ho8NnLn7VfwvTAX1D\n" \
"rUpr8I8+IOR1+2U=\n" \
"-----END PRIVATE KEY-----\n" };

std::string PrivateKeyTest::pem_key { "-----BEGIN PRIVATE KEY-----\n" \
"MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBANczYW4BnoSX4RmN\n" \
"ZV84UEo4yclkB8JhEzLmFMGyKreZ6m4aXSSedEAvLQ0iPahV45w8OC5Jn45aPnf7\n" \
"HIdi9xVTRVnzlxkZPiInwwLzllZY2o3qyg0xlOmKCr44BpsztY16yXOSAxFJFdXY\n" \
"mzq2uOMQLWInTTLF50DjMCnEVH5zAgMBAAECgYAoo3NKqtOchnHjuWfjS2ceHQs+\n" \
"FL3CX0KY4goZaePXOCGlGSVtvN6HIGGJkWXDXDTXVCfn1c9juncBgVIp3u55p9Hm\n" \
"YYfW/ELLFhn2bVwXdOWKSIJ8Jt1ftaYWOvNWQ2J7Ez1vX3w9FFmxblTu8SE7V04V\n" \
"E6nr96t2LdXGoAagAQJBAOr6z71z3OYjytNXe3D6yAEoe6TdKAnAzIYRVAIsat7V\n" \
"3C+y9NgAk6uhKv+xTcrYYlh7oTvDAZ6nBXnB47/1HgECQQDqc53VM8XLo96s2SZi\n" \
"8tSm25/M3BXHfJpjVlXVrNJdTEfDYeaMGLx8YoKigREJVD9XWsj+GC7NvLf+Hew0\n" \
"wARzAkEAg9ge38o209qZX2Pim03bEutIFQUSBgbruv3WCTIq9MVCOnFK+De6o75W\n" \
"hglSANLQu50CpqmQKxjD9cFYrMg4AQJBANmEKMP8Q596Soas9PtKddbU3n6PFjm9\n" \
"NfPBzuLuc0GSGuZ/twj1jjIMp0yjWC4Clr2yAdYUk5/XXhEKq/II0FcCQHKREhyI\n" \
"fAnJ/ZDvM9MbsSGZkf9VDQIkZjZ1l9Py6u3IZM3gM8fA/IdNxhj/r7uWgdPW6Z4D\n" \
"404/gKsy8/wOCkM=\n" \
"-----END PRIVATE KEY-----\n" };

TEST_F(PrivateKeyTest, GenKeyFromEvp) {
  genKeyFromEvp();
}

TEST_F(PrivateKeyTest, GenKeyFromPem) {
  genKeyFromPem();
}

TEST_F(PrivateKeyTest, GenKeyFromPemPass) {
  genKeyFromPemPass();
}

TEST_F(PrivateKeyTest, GenKeyFromDer) {
  genKeyFromDer();
}

TEST_F(PrivateKeyTest, TestKeyPem) {
  testKeyFromPem( genKeyFromPem() );
}

TEST_F(PrivateKeyTest, TestKeyDer) {
  testKeyFromDer( genKeyFromDer() );
}

TEST_F(PrivateKeyTest, SizeTestBitsEq) {
  testSizeBits( genKeyFromPem() );
}

TEST_F(PrivateKeyTest, SizeTestBytesEq) {
  testSizeBytes( genKeyFromPem() );
}

TEST_F(PrivateKeyTest, EqualsTest) {
  testEquals();
}

TEST_F(PrivateKeyTest, EvpTest) {
  testEvp();
}

