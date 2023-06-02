#include "libcryptosec/certificate/GeneralNames.h"
#include <libcryptosec/ByteArray.h>
#include <libcryptosec/certificate/BasicConstraintsExtension.h>
#include <openssl/asn1.h>
#include <openssl/x509v3.h>
#include <sstream>
#include <gtest/gtest.h>


/**
 * @brief Testes unitários da classe Extension e seus derivados
 */
class BasicConstraintsExtensionTest : public ::testing::Test {

protected:
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    BasicConstraintsExtension DefaultConstructor() {
      BasicConstraintsExtension ext {};
      return ext;
    }

    BasicConstraintsExtension ExtensionConstructor() {
      X509_EXTENSION *ret;
      BASIC_CONSTRAINTS_st *basicConstraints;
      basicConstraints = BASIC_CONSTRAINTS_new();
      basicConstraints->ca = 0;
      basicConstraints->pathlen = ASN1_INTEGER_new();
      ASN1_INTEGER_set(basicConstraints->pathlen, path);
      ret = X509V3_EXT_i2d(NID_basic_constraints, false, (void *)basicConstraints);

      auto ext = BasicConstraintsExtension(ret);

      return ext;
    }

    void XmlEncoded(BasicConstraintsExtension ext) {
      std::string tab = "";
      std::string expected = tab + "<basicConstraints>\n" +
        tab + "\t<extnID>basicConstraints</extnID>\n" +
        tab + "\t<critical>no</critical>\n" +
        tab + "\t<extnValue>\n" +
        tab + "\t\t<ca>false</ca>\n" +
        tab + "\t\t<pathLenConstraint>-1</pathLenConstraint>\n" + 
        tab + "\t</extnValue>\n" +
        tab + "</basicConstraints>\n";
      ASSERT_EQ(ext.getXmlEncoded(), expected);
    }

    void XmlEncodedTab(BasicConstraintsExtension ext) {
      std::string expected = tab + "<basicConstraints>\n" +
        tab + "\t<extnID>basicConstraints</extnID>\n" +
        tab + "\t<critical>no</critical>\n" +
        tab + "\t<extnValue>\n" +
        tab + "\t\t<ca>false</ca>\n" +
        tab + "\t\t<pathLenConstraint>-1</pathLenConstraint>\n" + 
        tab + "\t</extnValue>\n" +
        tab + "</basicConstraints>\n";
      ASSERT_EQ(ext.getXmlEncoded(tab), expected);
    }

    void SetPath(BasicConstraintsExtension ext) {
      ext.setPathLen(path);
      ASSERT_EQ(ext.getPathLen(), path);
    }

    void GetPath(BasicConstraintsExtension ext) {
      ASSERT_EQ(ext.getPathLen(), -1);
    }

    void GetPathX509(BasicConstraintsExtension ext) {
      ASSERT_EQ(ext.getPathLen(), path);
    }

    void SetCA(BasicConstraintsExtension ext) {
      ext.setCa(true);
      ASSERT_EQ(ext.isCa(), true);
    }

    void GetCA(BasicConstraintsExtension ext) {
      ASSERT_EQ(false, ext.isCa());
    }

    void GetExtension(BasicConstraintsExtension ext) {
      ext.setPathLen(path);

      BASIC_CONSTRAINTS_st *basicConstraints;
      basicConstraints = (BASIC_CONSTRAINTS_st *)X509V3_EXT_d2i(ext.getX509Extension());
      auto path_extracted = ASN1_INTEGER_get(basicConstraints->pathlen);
      ASSERT_EQ(path_extracted, path);
    }

    void GetOid(BasicConstraintsExtension ext) {
      ObjectIdentifier oid { ext.getObjectIdentifier() };
      auto expected = ObjectIdentifierFactory::getObjectIdentifier(NID_authority_key_identifier);
      ASSERT_EQ(oid.getOid(), expected.getOid());
    }

    void GetName(BasicConstraintsExtension ext) {
      ASSERT_EQ(ext.getName(), name);
    }

    void GetType(BasicConstraintsExtension ext) {
      ASSERT_EQ(ext.getTypeName(), Extension::BASIC_CONSTRAINTS);
    }

    void SetCritical(BasicConstraintsExtension ext) {
      ext.setCritical(true);
      ASSERT_EQ(ext.isCritical(), true);
    }

    void IsCritical(BasicConstraintsExtension ext) {
      ASSERT_EQ(ext.isCritical(), false);
    }

    static std::string tab;
    static std::string name;
    static long path;
    static std::string info;

};

std::string BasicConstraintsExtensionTest::tab = "tab";
std::string BasicConstraintsExtensionTest::info = "info";
long BasicConstraintsExtensionTest::path {22};
std::string BasicConstraintsExtensionTest::name = "basicConstraints";

TEST_F(BasicConstraintsExtensionTest, ConstructorTest) {
  DefaultConstructor();
}

TEST_F(BasicConstraintsExtensionTest, ExtensionConstructorTest) {
  ExtensionConstructor();
}

TEST_F(BasicConstraintsExtensionTest, getCAX509Test) {
  GetCA(ExtensionConstructor());
}

TEST_F(BasicConstraintsExtensionTest, getPathX509Test) {
  GetPathX509(ExtensionConstructor());
}

TEST_F(BasicConstraintsExtensionTest, XmlTest) {
  XmlEncoded(DefaultConstructor());
}

TEST_F(BasicConstraintsExtensionTest, IsCriticalX509Test) {
  IsCritical(ExtensionConstructor());
}

TEST_F(BasicConstraintsExtensionTest, XmlTabbedTest) {
  XmlEncodedTab(DefaultConstructor());
}

TEST_F(BasicConstraintsExtensionTest, setCATest) {
  SetCA(DefaultConstructor());
}

TEST_F(BasicConstraintsExtensionTest, getCATest) {
  GetCA(DefaultConstructor());
}

TEST_F(BasicConstraintsExtensionTest, IsCriticalTest) {
  IsCritical(DefaultConstructor());
}

TEST_F(BasicConstraintsExtensionTest, SetCriticalTest) {
  SetCritical(DefaultConstructor());
}

TEST_F(BasicConstraintsExtensionTest, GetNameTest) {
  GetName(DefaultConstructor());
}

TEST_F(BasicConstraintsExtensionTest, GetTypeTest) {
  GetType(DefaultConstructor());
}

TEST_F(BasicConstraintsExtensionTest, SetPathTest) {
  SetPath(DefaultConstructor());
}

TEST_F(BasicConstraintsExtensionTest, getPathTest) {
  GetPath(DefaultConstructor());
}

TEST_F(BasicConstraintsExtensionTest, getExtensionTest) {
  GetExtension(DefaultConstructor());
}

