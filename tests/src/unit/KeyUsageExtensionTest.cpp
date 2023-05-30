#include <libcryptosec/certificate/KeyUsageExtension.h>

#include <sstream>
#include <gtest/gtest.h>
#include <stdlib.h>

/**
 * @brief Testes unitários da classe GeneralName
 */
class KeyUsageExtensionTest : public ::testing::Test {

protected:
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    KeyUsageExtension genEmpty() {
      return KeyUsageExtension();
    }

    KeyUsageExtension genKeyUsage() {
      KeyUsageExtension ext;

      for (unsigned int i = 0; i < 9; i++) {
        KeyUsageExtension::Usage usage = (KeyUsageExtension::Usage) i;
        ext.setUsage(usage, usages.at(i));
      }

      return ext;
    }

    std::string genValue2Xml(std::string tab = "") {
      std::string ret;

      for (unsigned int i = 0; i < 9; i++) {
        KeyUsageExtension::Usage usage = (KeyUsageExtension::Usage) i;
        std::string name = KeyUsageExtension::usage2Name(usage);
        std::string value = usages.at(i) ? "1" : "0";

        ret += tab + "<" + name + ">" + value + "</" + name + ">\n";
      }

      return ret;
    }

    std::string genXml() {
      std::string ret;
      std::string ext2Value;

      ext2Value = genValue2Xml("\t\t");

      ret = "<keyUsage>\n";
      ret += "\t<extnID>" + name + "</extnID>\n";
      ret += "\t<critical>no</critical>\n";
      ret += "\t<extnValue>\n";
      ret += ext2Value;
      ret += "\t</extnValue>\n";
      ret += "</keyUsage>\n";
      
      return ret;
    }

    void testExtension(KeyUsageExtension ext) {
      ObjectIdentifier obj = ext.getObjectIdentifier();

      ASSERT_EQ(obj.getOid(), oid);
      ASSERT_EQ(obj.getName(), name);

      ASSERT_FALSE(ext.isCritical());
    }

    void testEmpty(KeyUsageExtension ext) {
      for (unsigned int i = 0; i < 9; i++) {
        KeyUsageExtension::Usage usage = (KeyUsageExtension::Usage) i;

        ASSERT_FALSE(ext.getUsage(usage));
      }
    }

    void testKeyUsage(KeyUsageExtension ext) {
      for (unsigned int i = 0; i < 9; i++) {
        KeyUsageExtension::Usage usage = (KeyUsageExtension::Usage) i;

        ASSERT_EQ(ext.getUsage(usage), usages.at(i));
      }
    }

    void testSanity() {
      KeyUsageExtension ext = genKeyUsage();
      X509_EXTENSION *x509 = ext.getX509Extension();
      KeyUsageExtension copy(x509);

      testExtension(copy);
      testKeyUsage(copy);
    }

    void testUsageNames() {
      for (unsigned int i = 0; i < 9; i++) {
        KeyUsageExtension::Usage usage = (KeyUsageExtension::Usage) i;
        
        ASSERT_EQ(KeyUsageExtension::usage2Name(usage), usageNames.at(i));
      }
    }

    void testValue2Xml() {
      KeyUsageExtension ext = genKeyUsage();
      std::string usage2Xml = genValue2Xml();

      ASSERT_EQ(ext.extValue2Xml(), usage2Xml);
    }

    void testXml() {
      KeyUsageExtension ext = genKeyUsage();
      std::string xml = genXml();
    
      ASSERT_EQ(ext.getXmlEncoded(), xml);
    }

    // void testThrow() {
    //   BASIC_CONSTRAINTS *ba = BASIC_CONSTRAINTS_new();
    //   X509_EXTENSION *ext = X509V3_EXT_i2d(NID_basic_constraints, 0, (void *)ba);
    //   BASIC_CONSTRAINTS_free(ba);
  
    //   ASSERT_THROW(KeyUsageExtension(ext), CertificationException);
    // }
  
    static std::string oid;
    static std::string name;
    static std::vector<bool> usages;
    static std::vector<std::string> usageNames;
};

/*
 * Initialization of variables used in the tests
 */
std::string KeyUsageExtensionTest::oid = "2.5.29.15";
std::string KeyUsageExtensionTest::name = "keyUsage";

std::vector<bool> KeyUsageExtensionTest::usages {true, true, false, true, true, true, true, false, false};

std::vector<std::string> KeyUsageExtensionTest::usageNames {"digitalSignature", "nonRepudiation", "keyEncipherment",
                                                       "dataEncipherment", "keyAgreement", "keyCertSign",
                                                       "crlSign", "encipherOnly", "decipherOnly"};

TEST_F(KeyUsageExtensionTest, Extension) {
  KeyUsageExtension ext = genEmpty();
  testExtension(ext);
}

TEST_F(KeyUsageExtensionTest, Empty) {
  KeyUsageExtension ext = genEmpty();
  testEmpty(ext);
}

TEST_F(KeyUsageExtensionTest, Usage) {
  KeyUsageExtension ext = genKeyUsage();
  testKeyUsage(ext);
}

TEST_F(KeyUsageExtensionTest, Sanity) {
  testSanity();
}

TEST_F(KeyUsageExtensionTest, UsageName) {
  testUsageNames();
}

TEST_F(KeyUsageExtensionTest, Value2Xml) {
  testValue2Xml();
}

TEST_F(KeyUsageExtensionTest, XMLEncoded) {
  testXml();
}

// TEST_F(KeyUsageExtensionTest, Throw) {
//   testThrow();
// }
