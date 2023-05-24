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

/**
 * @brief Testes unitários da classe RSAPrivateKey
 */
class RSAPrivateKeyTest: public ::testing::Test {
  protected:
    using KeyPair = std::pair<RSAPrivateKey, PrivateKey>;
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

  /**
   * @brief Gera uma par de chaves RSA a partir de um PEM
   */
    KeyPair genPairPem() {
      RSAPrivateKey first { genKeyFromPem() };
      RSAPrivateKey second { genKeyFromPem() };
      return std::make_pair(first, second);
    }

  /**
   * @brief Gera uma chave RSA a partir de uma chave EVP do OpenSSL
   */
    RSAPrivateKey genKeyFromEvp() {
      RSA *rsa = RSA_new();
      EVP_PKEY *key = EVP_PKEY_new();
      EVP_PKEY_assign_RSA(key, rsa);
      RSAPrivateKey chave { key };
      return chave;
    }

  /**
   * @brief Testas as chaves Evp extraídas do wrapper
   */
    void testEvp() {
      BIO *buffer { BIO_new( BIO_s_mem() )};
      BIO_write(buffer, pem_key.c_str(), pem_key.size());

      RSA *rsa = RSA_new();
      EVP_PKEY *key = EVP_PKEY_new();
      EVP_PKEY_assign_RSA(key, rsa);
      key = PEM_read_bio_PrivateKey(buffer, nullptr, nullptr, nullptr);

      RSAPrivateKey chave { key };

      ASSERT_TRUE(chave.getEvpPkey() == key);
    }

  /**
   * @brief Gera uma Chave a partir de um DerEncoded (ByteArray)
   */
    RSAPrivateKey genKeyFromDer() {
      BIO *buffer;
      buffer = BIO_new(BIO_s_mem());
      BIO_write(buffer, pem_key.c_str(), pem_key.size());
      EVP_PKEY *key = PEM_read_bio_PrivateKey(buffer, NULL, NULL, NULL);

      unsigned char *data;
      buffer = BIO_new(BIO_s_mem());
      i2d_PrivateKey_bio(buffer, key);
      int ndata = BIO_get_mem_data(buffer, &data);
      ByteArray ret (data, ndata);

      RSAPrivateKey chave ( ret );
      return chave;
    }

  /**
   * @brief Gera uma chave com o PEM
   */
    RSAPrivateKey genKeyFromPem() {
      RSAPrivateKey chave ( pem_key );
      return chave;
    }

  /**
   * @brief Gera chaves RSA a prtir de um PEM com senha
   */
    RSAPrivateKey genKeyFromPemPass() {
      RSAPrivateKey chave (pem_key_pass, pass);
      return chave;
    }

  /**
   * @brief Testas as chaves geradas a partir de um DER (ByteArray)
   */
    void testKeyFromDer(RSAPrivateKey passed_key) {
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

  /**
   * @brief Teste de sanidade para chaves geradas a partir do PEM
   */
    void testKeyFromPem(RSAPrivateKey key) {
      std::string key_pem { key.getPemEncoded() };
      ASSERT_TRUE(key_pem == pem_key); 
    }

  /**
   * @brief Checa o tamanho do menor buffer para o máximo 
   * necessário para as operações do OpenSSL, checar documentação,
   * o tamanho aqui bate por acaso
   */
    void testSizeBits(RSAPrivateKey key) {
      ASSERT_EQ(key.getSizeBits(), size);
    }

  /**
   * @brief Checa o tamanho da chave
   */
    void testSizeBytes(RSAPrivateKey key) {
      ASSERT_EQ(key.getSize(), size / 8);
    }

  /**
   * @brief Teste de sanidade para a igualdade
   */
    void testEquals() {
      RSAPrivateKey chave ( pem_key );
      RSAPrivateKey chave2 ( pem_key );
      ASSERT_EQ(chave.getPemEncoded(), chave2.getPemEncoded());
    }

    static int size;
    static std::string pem_key;
    static std::string pem_key_pass;
    static ByteArray pass;
};

int RSAPrivateKeyTest::size {1024};

ByteArray RSAPrivateKeyTest::pass { "12345" };
std::string RSAPrivateKeyTest::pem_key_pass { "-----BEGIN PRIVATE KEY-----\n" \
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

std::string RSAPrivateKeyTest::pem_key { "-----BEGIN PRIVATE KEY-----\n" \
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

TEST_F(RSAPrivateKeyTest, GenKeyFromEvp) {
  genKeyFromEvp();
}

TEST_F(RSAPrivateKeyTest, GenKeyFromPem) {
  genKeyFromPem();
}

TEST_F(RSAPrivateKeyTest, GenKeyFromPemPass) {
  genKeyFromPemPass();
}

TEST_F(RSAPrivateKeyTest, GenKeyFromDer) {
  genKeyFromDer();
}

TEST_F(RSAPrivateKeyTest, TestKeyPem) {
  testKeyFromPem( genKeyFromPem() );
}

TEST_F(RSAPrivateKeyTest, TestKeyDer) {
  testKeyFromDer( genKeyFromDer() );
}

TEST_F(RSAPrivateKeyTest, SizeTestBitsEq) {
  testSizeBits( genKeyFromPem() );
}

TEST_F(RSAPrivateKeyTest, SizeTestBytesEq) {
  testSizeBytes( genKeyFromPem() );
}

TEST_F(RSAPrivateKeyTest, EqualsTest) {
  testEquals();
}

TEST_F(RSAPrivateKeyTest, EvpTest) {
  testEvp();
}
