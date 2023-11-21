#include <libcryptosec/certificate/ExtendedKeyUsageExtension.h>
#include <libcryptosec/certificate/BasicConstraintsExtension.h>
#include <libcryptosec/certificate/ObjectIdentifierFactory.h>

#include <sstream>
#include <gtest/gtest.h>
#include <stdlib.h>

/**
 * @brief Testes unitários da classe GeneralName
 */
class ExtendedKeyUsageExtensionTest : public ::testing::Test {

protected:
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    ExtendedKeyUsageExtension genEmpty() {
      return ExtendedKeyUsageExtension();
    }

    ExtendedKeyUsageExtension genExtendedKeyUsageExtension() {
      ExtendedKeyUsageExtension ext;

      ext.addUsage(ObjectIdentifierFactory::getObjectIdentifier(ekuOneOid));
      ext.addUsage(ObjectIdentifierFactory::getObjectIdentifier(ekuTwoOid));

      return ext;
    }

    std::string genExtValue2Xml(std::string tab = "", bool empty = false) {
      std::string ret = "";

      if (!empty) {
        ret += tab + "<usage>" + ekuOneName + "</usage>\n";
        ret += tab + "<usage>" + ekuTwoName + "</usage>\n";
      }

      return ret;
    }

    std::string genXml(std::string tab = "", bool empty = false) {
      std::string ret = tab + "<extendedKeyUsage>\n";

      ret += tab + "\t<extnID>" + extName + "</extnID>\n";
      ret += tab + "\t<critical>no</critical>\n";
      if (!empty) {
        ret += genExtValue2Xml(tab + "\t\t");
      }
      ret += tab + "</extendedKeyUsage>\n";

      return ret;
    }

    void testEmpty(ExtendedKeyUsageExtension ext) {
      std::vector<ObjectIdentifier> oids = ext.getUsages();

      ASSERT_EQ(oids.size(), 0);
    }

    void testExtendedKeyUsageExtension(ExtendedKeyUsageExtension ext, bool sanity = false) {
      ObjectIdentifier oid;
      std::vector<ObjectIdentifier> oids = ext.getUsages();

      ASSERT_EQ(oids.size(), 2);

      // Sanity recreates the values backwards, so we test it backwards as well
      if (sanity) {
        oid = oids.back();
        oids.pop_back();
      } else {
        oid = oids.front();
        oids.erase(oids.begin());
      }

      ASSERT_EQ(oid.getOid(), ekuOneOid);
      ASSERT_EQ(oid.getName(), ekuOneName);

      // Only one OID remaning, be wary of this if you plan to modify the test
      oid = oids.front();

      ASSERT_EQ(oid.getOid(), ekuTwoOid);
      ASSERT_EQ(oid.getName(), ekuTwoName);
    }

    void testSanityEmpty() {
      ExtendedKeyUsageExtension ext = genEmpty();
      X509_EXTENSION *x509 = ext.getX509Extension();
      ExtendedKeyUsageExtension copy(x509);

      testEmpty(copy);
    }

    void testSanity() {
      ExtendedKeyUsageExtension ext = genExtendedKeyUsageExtension();
      X509_EXTENSION *x509 = ext.getX509Extension();
      ExtendedKeyUsageExtension copy(x509);

      testExtendedKeyUsageExtension(copy, true);
    }

    void testSanityWrongExtension() {
      BasicConstraintsExtension bc;
      X509_EXTENSION *x509 = bc.getX509Extension();
      ASSERT_THROW(ExtendedKeyUsageExtension copy(x509), CertificationException);
    }

    void testExtValue2Xml(std::string tab = "", bool empty = false) {
      std::string xml = genExtValue2Xml(tab, empty);
      ExtendedKeyUsageExtension ext;
      
      if (!empty) {
        ext = genExtendedKeyUsageExtension();
      }

      if (tab == "") {
        ASSERT_EQ(ext.extValue2Xml(), xml);
        return;
      }

      ASSERT_EQ(ext.extValue2Xml(tab), xml);
    }

    void testXml(std::string tab = "", bool empty = false) {
      std::string xml = genXml(tab, empty);
      ExtendedKeyUsageExtension ext;
      
      if (!empty) {
        ext = genExtendedKeyUsageExtension();
      }

      if (tab == "") {
        ASSERT_EQ(ext.getXmlEncoded(), xml);
        return;
      }

      ASSERT_EQ(ext.getXmlEncoded(tab), xml);
    }

    static std::string ekuOneOid;
    static std::string ekuOneName;
    static std::string ekuTwoOid;
    static std::string ekuTwoName;
    static std::string extName;
};

/*
 * Initialization of variables used in the tests
 */
std::string ExtendedKeyUsageExtensionTest::ekuOneOid = "1.3.6.1.5.5.7.3.1";
std::string ExtendedKeyUsageExtensionTest::ekuOneName = "serverAuth";
std::string ExtendedKeyUsageExtensionTest::ekuTwoOid = "1.3.6.1.5.5.7.3.4";
std::string ExtendedKeyUsageExtensionTest::ekuTwoName = "emailProtection";
std::string ExtendedKeyUsageExtensionTest::extName = "extendedKeyUsage";

TEST_F(ExtendedKeyUsageExtensionTest, Empty) {
  ExtendedKeyUsageExtension ext = genEmpty();
  testEmpty(ext);
}

TEST_F(ExtendedKeyUsageExtensionTest, Usage) {
  ExtendedKeyUsageExtension ext = genExtendedKeyUsageExtension();
  testExtendedKeyUsageExtension(ext);
}

TEST_F(ExtendedKeyUsageExtensionTest, SanityEmpty) {
  testSanityEmpty();
}

TEST_F(ExtendedKeyUsageExtensionTest, Sanity) {
  testSanity();
}

TEST_F(ExtendedKeyUsageExtensionTest, SanityWrongExtension) {
  testSanityWrongExtension();
}

TEST_F(ExtendedKeyUsageExtensionTest, ExtValue2XmlEmpty) {
  testExtValue2Xml("", true);
}

TEST_F(ExtendedKeyUsageExtensionTest, ExtValue2Xml) {
  testExtValue2Xml();
}

TEST_F(ExtendedKeyUsageExtensionTest, ExtValue2XmlTab) {
  testExtValue2Xml("tab");
}

TEST_F(ExtendedKeyUsageExtensionTest, XmlEmpty) {
  testXml("", true);
}

TEST_F(ExtendedKeyUsageExtensionTest, Xml) {
  testXml();
}

TEST_F(ExtendedKeyUsageExtensionTest, XmlTab) {
  testXml("tab");
}
