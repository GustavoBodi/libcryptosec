#include <libcryptosec/AsymmetricKey.h>
#include <libcryptosec/RSAKeyPair.h>
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

class RSAKeyPairTest: public ::testing::Test {
  protected:
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    RSAKeyPair genKeysFromPem() {
      RSAKeyPair chave (1024);
      return chave;
    }

    void getAlgoTest(RSAKeyPair pair) {
      ASSERT_EQ(pair.getAlgorithm(), AsymmetricKey::RSA);
    }

    void testValidGen(RSAKeyPair pair) {
      std::string private_key { pair.getPrivateKey()->getPemEncoded() };
      BIO *bo = BIO_new( BIO_s_mem() );
      BIO_write(bo, private_key.c_str(), private_key.length());
      RSA *priv_key = RSA_new();
      PEM_read_bio_RSAPrivateKey(bo, &priv_key, nullptr, nullptr);

      // Now for the public key

      std::string public_key { pair.getPublicKey()->getPemEncoded() };
      BIO *bo_pub = BIO_new( BIO_s_mem() );
      BIO_write(bo_pub, public_key.c_str(), public_key.length());
      RSA *pub_key = RSA_new();
      PEM_read_bio_RSA_PUBKEY(bo_pub, &pub_key, nullptr, nullptr);

      const BIGNUM *n_pub = RSA_get0_n(pub_key);
      const BIGNUM *n_priv = RSA_get0_n(priv_key);

      // Checking if the generated key is valid
      
      std::cout << n_pub << std::endl;
      std::cout << n_priv << std::endl;
      ASSERT_TRUE( BN_cmp(n_pub, n_priv) == 0 );
    }

    void testSizeBits(RSAKeyPair keys) {
      ASSERT_EQ(keys.getPrivateKey()->getSizeBits(), size);
      ASSERT_EQ(keys.getPublicKey()->getSizeBits(), size);
    }

    void testSizeBytes(RSAKeyPair keys) {
      ASSERT_EQ(keys.getPrivateKey()->getSize(), size / 8);
      ASSERT_EQ(keys.getPublicKey()->getSize(), size / 8);
    }

    void pemSanityTest(RSAKeyPair pair) {
      std::string priv_key = pair.getPemEncoded();
      ASSERT_EQ(priv_key, pair.getPrivateKey()->getPemEncoded());
    }

    void derSanityTest(RSAKeyPair pair) {
      ByteArray priv_key = pair.getDerEncoded();
      ASSERT_EQ(priv_key, pair.getPrivateKey()->getDerEncoded());
    }

    void evpSanityTest(RSAKeyPair pair) {
      EVP_PKEY *key = pair.getEvpPkey();
      ASSERT_EQ(key, pair.getPrivateKey()->getEvpPkey());
    }

    static int size;
    static std::string pem_key;
    static std::string pem_key_pass;
    static ByteArray pass;
};

int RSAKeyPairTest::size {1024};

ByteArray RSAKeyPairTest::pass { "12345" };
std::string RSAKeyPairTest::pem_key_pass { "-----BEGIN PRIVATE KEY-----\n" \
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

std::string RSAKeyPairTest::pem_key { "-----BEGIN PRIVATE KEY-----\n" \
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

TEST_F(RSAKeyPairTest, GenKey) {
  genKeysFromPem();
}

TEST_F(RSAKeyPairTest, GeneratedKeyTest) {
  testValidGen(genKeysFromPem());
}

TEST_F(RSAKeyPairTest, AlgorithmTest) {
  getAlgoTest(genKeysFromPem());
}

TEST_F(RSAKeyPairTest, EvpSanityTest) {
  evpSanityTest( genKeysFromPem() );
}

TEST_F(RSAKeyPairTest, DerSanityTest) {
  derSanityTest( genKeysFromPem() );
}

TEST_F(RSAKeyPairTest, PemSanityTest) {
  pemSanityTest( genKeysFromPem() );
}

TEST_F(RSAKeyPairTest, SizeTestBitsEq) {
  testSizeBits( genKeysFromPem() );
}

TEST_F(RSAKeyPairTest, SizeTestBytesEq) {
  testSizeBytes( genKeysFromPem() );
}

