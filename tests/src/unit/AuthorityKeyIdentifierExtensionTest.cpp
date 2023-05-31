#include <libcryptosec/ByteArray.h>
#include <libcryptosec/certificate/AuthorityKeyIdentifierExtension.h>
#include <openssl/asn1.h>
#include <sstream>
#include <gtest/gtest.h>


/**
 * @brief Testes unitários da classe Extension e seus derivados
 */
class AuthorityKeyIdentifierExtensionTest : public ::testing::Test {

protected:
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    AuthorityKeyIdentifierExtension DefaultConstructor() {
      AuthorityKeyIdentifierExtension ext {};
      return ext;
    }

    AuthorityKeyIdentifierExtension ExtensionConstructor() {
      ByteArray data {"identifier"};
      AUTHORITY_KEYID *auth_key = AUTHORITY_KEYID_new();
      auth_key->keyid = ASN1_OCTET_STRING_new();
      ASN1_OCTET_STRING_set(auth_key->keyid, data.getDataPointer(), data.size());

      auth_key->serial = ASN1_INTEGER_new();
      ASN1_INTEGER_set(auth_key->serial, serialNumber);

      X509_EXTENSION *ret = X509_EXTENSION_new();
      ASN1_OCTET_STRING *octetString = ASN1_OCTET_STRING_new();
      ASN1_OCTET_STRING_set(octetString, data.getDataPointer(), data.size());
      ret = X509V3_EXT_i2d(NID_authority_key_identifier, 0, (void *)auth_key);
      auto ext = AuthorityKeyIdentifierExtension(ret);
      return ext;
    }

    void XmlEncoded(AuthorityKeyIdentifierExtension ext) {
      std::string tab = "";
      std::string expected = tab + "<authorityKeyIdentifier>\n" +
        tab + "\t<extnID>authorityKeyIdentifier</extnID>\n" +
        tab + "\t<critical>no</critical>\n" +
        tab + "\t<extnValue>\n" +
        tab + "\t</extnValue>\n" + 
        tab + "</authorityKeyIdentifier>\n";
      ASSERT_EQ(ext.getXmlEncoded(), expected);
    }

    void XmlEncodedTab(AuthorityKeyIdentifierExtension ext) {
      std::string expected = tab + "<authorityKeyIdentifier>\n" +
        tab + "\t<extnID>authorityKeyIdentifier</extnID>\n" +
        tab + "\t<critical>no</critical>\n" +
        tab + "\t<extnValue>\n" +
        tab + "\t</extnValue>\n" + 
        tab + "</authorityKeyIdentifier>\n";
      ASSERT_EQ(ext.getXmlEncoded(tab), expected);

    }

    void SetKey(AuthorityKeyIdentifierExtension ext) {
      ext.setKeyIdentifier(info);
      ASSERT_EQ(info, ext.getKeyIdentifier());
    }

    void GetKey(AuthorityKeyIdentifierExtension ext) {
      ByteArray default_key = ByteArray("");
      ASSERT_EQ(default_key, ext.getKeyIdentifier());
    }

    void GetExtension(AuthorityKeyIdentifierExtension ext) {
      X509_EXTENSION *x509ext = ext.getX509Extension();

      X509_EXTENSION *ret;
      ASN1_OCTET_STRING *octetString;
      ByteArray data;
      
      ret = X509_EXTENSION_new();
      octetString = ASN1_OCTET_STRING_new();
      data = ext.getKeyIdentifier();
      ASN1_OCTET_STRING_set(octetString, data.getDataPointer(), data.size());
      ret = X509V3_EXT_i2d(NID_authority_key_identifier, false, (void *)octetString);

      ASSERT_EQ(x509ext, ret);
    }

    void GetOid(AuthorityKeyIdentifierExtension ext) {
      ObjectIdentifier oid { ext.getObjectIdentifier() };
      auto expected = ObjectIdentifierFactory::getObjectIdentifier(NID_authority_key_identifier);
      ASSERT_EQ(oid.getOid(), expected.getOid());
    }

    void GetName(AuthorityKeyIdentifierExtension ext) {
      ASSERT_EQ(ext.getName(), name);
    }

    void GetType(AuthorityKeyIdentifierExtension ext) {
      ASSERT_EQ(ext.getTypeName(), Extension::AUTHORITY_KEY_IDENTIFIER);
    }

    void SetCritical(AuthorityKeyIdentifierExtension ext) {
      ext.setCritical(true);
      ASSERT_EQ(ext.isCritical(), true);
    }

    void IsCritical(AuthorityKeyIdentifierExtension ext) {
      ASSERT_EQ(ext.isCritical(), false);
    }

    static std::string tab;
    static std::string name;
    static long serialNumber;
    static std::string info;

};

std::string AuthorityKeyIdentifierExtensionTest::tab = "tab";
std::string AuthorityKeyIdentifierExtensionTest::info = "info";
long AuthorityKeyIdentifierExtensionTest::serialNumber {12345};
std::string AuthorityKeyIdentifierExtensionTest::name = "authorityKeyIdentifier";

TEST_F(AuthorityKeyIdentifierExtensionTest, ConstructorTest) {
  DefaultConstructor();
}

TEST_F(AuthorityKeyIdentifierExtensionTest, ExtensionConstructorTest) {
  ExtensionConstructor();
}

TEST_F(AuthorityKeyIdentifierExtensionTest, XmlTest) {
  XmlEncoded(DefaultConstructor());
}

TEST_F(AuthorityKeyIdentifierExtensionTest, XmlTabbedTest) {
  XmlEncodedTab(DefaultConstructor());
}

TEST_F(AuthorityKeyIdentifierExtensionTest, SetKeyTest) {
  SetKey(DefaultConstructor());
}

TEST_F(AuthorityKeyIdentifierExtensionTest, IsCriticalTest) {
  IsCritical(DefaultConstructor());
}

TEST_F(AuthorityKeyIdentifierExtensionTest, SetCriticalTest) {
  SetCritical(DefaultConstructor());
}

TEST_F(AuthorityKeyIdentifierExtensionTest, GetNameTest) {
  GetName(DefaultConstructor());
}

TEST_F(AuthorityKeyIdentifierExtensionTest, GetTypeTest) {
  GetType(DefaultConstructor());
}

