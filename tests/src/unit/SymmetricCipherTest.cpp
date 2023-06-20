#include <libcryptosec/SymmetricCipher.h>
#include <libcryptosec/SymmetricKeyGenerator.h>

#include <sstream>
#include <gtest/gtest.h>
#include <stdlib.h>

/**
 * @brief Testes unitários da classe SymmetricCipher
 */
class SymmetricCipherTest : public ::testing::Test {

protected:
    virtual void SetUp() {
      key = SymmetricKeyGenerator::generateKey(keyAlgorithm);
    }

    virtual void TearDown() {
    }

    SymmetricCipher genEmpty() {
      return SymmetricCipher();
    }

    SymmetricCipher genInitNoMode(SymmetricCipher::Operation operation) {
      SymmetricCipher sc;

      sc.init(*key, operation);

      return sc;
    }

    SymmetricCipher genInit(SymmetricCipher::OperationMode mode, SymmetricCipher::Operation operation) {
      SymmetricCipher sc;

      sc.init(*key, mode, operation);

      return sc;
    }

    ByteArray encryptFromString(SymmetricCipher::OperationMode mode) {
      SymmetricCipher sc = genInit(mode, SymmetricCipher::ENCRYPT);

      return sc.doFinal(data);
    }

    ByteArray encryptFromByteArray(SymmetricCipher::OperationMode mode) {
      SymmetricCipher sc = genInit(mode, SymmetricCipher::ENCRYPT);

      return sc.doFinal(baData);
    }

    ByteArray decryptData(SymmetricCipher::OperationMode mode, ByteArray encryptedData) {
      SymmetricCipher sc = genInit(mode, SymmetricCipher::DECRYPT);

      return sc.doFinal(encryptedData);
    }

    void testEmpty(SymmetricCipher sc) {
      ASSERT_THROW(sc.getOperation(), InvalidStateException);
      ASSERT_THROW(sc.getOperationMode(), InvalidStateException);
    }

    void testInitNoMode(SymmetricCipher sc, SymmetricCipher::Operation operation) {
      ASSERT_EQ(sc.getOperation(), operation);
      ASSERT_EQ(sc.getOperationMode(), SymmetricCipher::CBC);
    }

    void testInit(SymmetricCipher sc, SymmetricCipher::OperationMode mode, SymmetricCipher::Operation operation) {
      ASSERT_EQ(sc.getOperation(), operation);
      ASSERT_EQ(sc.getOperationMode(), mode);
    }

    void testEncryptDecryptString(SymmetricCipher::OperationMode mode) {
      ByteArray encryptedData = encryptFromString(mode);
      ByteArray decryptedData = decryptData(mode, encryptedData);

      ASSERT_NE(encryptedData.toString(), data);
      ASSERT_EQ(decryptedData.toString(), data);
    }

    void testEncryptDecryptByteArray(SymmetricCipher::OperationMode mode) {
      ByteArray encryptedData = encryptFromByteArray(mode);
      ByteArray decryptedData = decryptData(mode, encryptedData);

      ASSERT_NE(encryptedData.toString(), data);
      ASSERT_EQ(decryptedData.toString(), data);
    }

    void testGetOperationModeNames() {
      for (unsigned int i = 0; i < 5; i++) {
        SymmetricCipher::OperationMode mode = (SymmetricCipher::OperationMode) i;
        ASSERT_EQ(SymmetricCipher::getOperationModeName(mode), operationModeNames.at(i));
      }
    }

    SymmetricKey *key;
    static SymmetricKey::Algorithm keyAlgorithm;
    static std::string data;
    static ByteArray baData;
    static std::vector<std::string> operationModeNames;
};

/*
 * Initialization of variables used in the tests
 */
SymmetricKey::Algorithm SymmetricCipherTest::keyAlgorithm = SymmetricKey::AES_256;
std::string SymmetricCipherTest::data = "clear data";
ByteArray SymmetricCipherTest::baData = ByteArray(SymmetricCipherTest::data);
std::vector<std::string> SymmetricCipherTest::operationModeNames {"", "cbc", "ecb", "cfb", "cbc"};

TEST_F(SymmetricCipherTest, InitTestCase) {
  SymmetricCipher::loadSymmetricCiphersAlgorithms();
}

TEST_F(SymmetricCipherTest, Empty) {
  SymmetricCipher sc = genEmpty();
  testEmpty(sc);
}

TEST_F(SymmetricCipherTest, InitNoModeEncrypt) {
  SymmetricCipher sc = genInitNoMode(SymmetricCipher::ENCRYPT);
  testInitNoMode(sc, SymmetricCipher::ENCRYPT);
}

TEST_F(SymmetricCipherTest, InitNoModeDecrypt) {
  SymmetricCipher sc = genInitNoMode(SymmetricCipher::DECRYPT);
  testInitNoMode(sc, SymmetricCipher::DECRYPT);
}

TEST_F(SymmetricCipherTest, InitCBCEncrypt) {
  SymmetricCipher sc = genInit(SymmetricCipher::CBC, SymmetricCipher::ENCRYPT);
  testInit(sc, SymmetricCipher::CBC, SymmetricCipher::ENCRYPT);
}

TEST_F(SymmetricCipherTest, InitCBCDecrypt) {
  SymmetricCipher sc = genInit(SymmetricCipher::CBC, SymmetricCipher::DECRYPT);
  testInit(sc, SymmetricCipher::CBC, SymmetricCipher::DECRYPT);
}

TEST_F(SymmetricCipherTest, InitECBEncrypt) {
  SymmetricCipher sc = genInit(SymmetricCipher::ECB, SymmetricCipher::ENCRYPT);
  testInit(sc, SymmetricCipher::ECB, SymmetricCipher::ENCRYPT);
}

TEST_F(SymmetricCipherTest, InitECBDecrypt) {
  SymmetricCipher sc = genInit(SymmetricCipher::ECB, SymmetricCipher::DECRYPT);
  testInit(sc, SymmetricCipher::ECB, SymmetricCipher::DECRYPT);
}

TEST_F(SymmetricCipherTest, InitCFBEncrypt) {
  SymmetricCipher sc = genInit(SymmetricCipher::CFB, SymmetricCipher::ENCRYPT);
  testInit(sc, SymmetricCipher::CFB, SymmetricCipher::ENCRYPT);
}

TEST_F(SymmetricCipherTest, InitCFBDecrypt) {
  SymmetricCipher sc = genInit(SymmetricCipher::CFB, SymmetricCipher::DECRYPT);
  testInit(sc, SymmetricCipher::CFB, SymmetricCipher::DECRYPT);
}

TEST_F(SymmetricCipherTest, InitOFBEncrypt) {
  SymmetricCipher sc = genInit(SymmetricCipher::OFB, SymmetricCipher::ENCRYPT);
  testInit(sc, SymmetricCipher::OFB, SymmetricCipher::ENCRYPT);
}

TEST_F(SymmetricCipherTest, InitOFBDecrypt) {
  SymmetricCipher sc = genInit(SymmetricCipher::OFB, SymmetricCipher::DECRYPT);
  testInit(sc, SymmetricCipher::OFB, SymmetricCipher::DECRYPT);
}

TEST_F(SymmetricCipherTest, EncryptDecryptStringCBC) {
  testEncryptDecryptString(SymmetricCipher::CBC);
}

TEST_F(SymmetricCipherTest, EncryptDecryptByteArrayCBC) {
  testEncryptDecryptByteArray(SymmetricCipher::CBC);
}

TEST_F(SymmetricCipherTest, EncryptDecryptStringECB) {
  testEncryptDecryptString(SymmetricCipher::ECB);
}

TEST_F(SymmetricCipherTest, EncryptDecryptByteArrayECB) {
  testEncryptDecryptByteArray(SymmetricCipher::ECB);
}

TEST_F(SymmetricCipherTest, EncryptDecryptStringCFB) {
  testEncryptDecryptString(SymmetricCipher::CFB);
}

TEST_F(SymmetricCipherTest, EncryptDecryptByteArrayCFB) {
  testEncryptDecryptByteArray(SymmetricCipher::CFB);
}

TEST_F(SymmetricCipherTest, EncryptDecryptStringOFB) {
  testEncryptDecryptString(SymmetricCipher::OFB);
}

TEST_F(SymmetricCipherTest, EncryptDecryptByteArrayOFB) {
  testEncryptDecryptByteArray(SymmetricCipher::OFB);
}

TEST_F(SymmetricCipherTest, GetOperationModeNames) {
  testGetOperationModeNames();
}
