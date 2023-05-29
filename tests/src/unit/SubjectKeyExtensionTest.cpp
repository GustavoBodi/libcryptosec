#include <libcryptosec/ByteArray.h>
#include <libcryptosec/certificate/SubjectKeyIdentifierExtension.h>
#include <sstream>
#include <gtest/gtest.h>


/**
 * @brief Testes unitários da classe Extension e seus derivados
 */
class SubjectKeyIdentifierExtensionTest : public ::testing::Test {

protected:
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    SubjectKeyIdentifierExtension DefaultConstructor() {
      SubjectKeyIdentifierExtension ext {};
      return ext;
    }

    SubjectKeyIdentifierExtension ExtensionConstructor() {

    }

    void XmlEncoded(SubjectKeyIdentifierExtension ext) {
      std::string tab = "";
      std::string expected = tab + "<subjectKeyIdentifier>\n" +
        tab + "\t<extnID>subjectKeyIdentifier</extnID>\n" +
        tab + "\t<critical>no</critical>\n" +
        tab + "\t<extnValue></extnValue>\n" + 
        tab + "</subjectKeyIdentifier>\n";
      ASSERT_EQ(ext.getXmlEncoded(), expected);
    }

    void XmlEncodedTab(SubjectKeyIdentifierExtension ext) {
      std::string tab = "teste";
      std::string expected = tab + "<subjectKeyIdentifier>\n" +
        tab + "\t<extnID>subjectKeyIdentifier</extnID>\n" +
        tab + "\t<critical>no</critical>\n" +
        tab + "\t<extnValue></extnValue>\n" + 
        tab + "</subjectKeyIdentifier>\n";
      ASSERT_EQ(ext.getXmlEncoded("teste"), expected);

    }

    void SetKey(SubjectKeyIdentifierExtension ext) {
      ByteArray key ("info");
      ext.setKeyIdentifier(key);
      ASSERT_EQ(key, ext.getKeyIdentifier());
    }

    void GetKey(SubjectKeyIdentifierExtension ext) {
      ByteArray default_key = ByteArray("");
      ASSERT_EQ(default_key, ext.getKeyIdentifier());
    }

    void GetExtension(SubjectKeyIdentifierExtension ext) {
      X509_EXTENSION *x509ext = ext.getX509Extension();

      X509_EXTENSION *ret;
      ASN1_OCTET_STRING *octetString;
      ByteArray data;
      
      ret = X509_EXTENSION_new();
      octetString = ASN1_OCTET_STRING_new();
      data = ext.getKeyIdentifier();
      ASN1_OCTET_STRING_set(octetString, data.getDataPointer(), data.size());
      ret = X509V3_EXT_i2d(NID_subject_key_identifier, false, (void *)octetString);

      ASSERT_EQ(x509ext, ret);
    }

    void GetOid(SubjectKeyIdentifierExtension ext) {
      ObjectIdentifier oid { ext.getObjectIdentifier() };
      auto expected = ObjectIdentifierFactory::getObjectIdentifier(NID_subject_key_identifier);
      ASSERT_EQ(oid.getOid(), expected.getOid());
    }

    void GetName(SubjectKeyIdentifierExtension ext) {
      auto expected = "subjectKeyIdentifier";
      ASSERT_EQ(ext.getName(), expected);
    }

    void GetType(SubjectKeyIdentifierExtension ext) {
      ASSERT_EQ(ext.getTypeName(), Extension::SUBJECT_KEY_IDENTIFIER);
    }

    void SetCritical(SubjectKeyIdentifierExtension ext) {
      ext.setCritical(true);
      ASSERT_EQ(ext.isCritical(), true);
    }

    void IsCritical(SubjectKeyIdentifierExtension ext) {
      ASSERT_EQ(ext.isCritical(), false);
    }

    void Ext2xml(SubjectKeyIdentifierExtension ext) {
      ByteArray subjKeyId;
      auto oid = ext.getKeyIdentifier();
      std::string tab = "val";
      std::string expected = tab + "<keyIdentifier>" + Base64::encode(oid) + "</keyIdentifier>\n";
      ASSERT_EQ(expected, ext.extValue2Xml("val"));
    }

};

TEST_F(SubjectKeyIdentifierExtensionTest, ConstructorTest) {
  DefaultConstructor();
}

TEST_F(SubjectKeyIdentifierExtensionTest, XmlTest) {
  XmlEncoded(DefaultConstructor());
}

TEST_F(SubjectKeyIdentifierExtensionTest, XmlTabbedTest) {
  XmlEncodedTab(DefaultConstructor());
}

TEST_F(SubjectKeyIdentifierExtensionTest, SetKeyTest) {
  SetKey(DefaultConstructor());
}

TEST_F(SubjectKeyIdentifierExtensionTest, IsCriticalTest) {
  IsCritical(DefaultConstructor());
}

TEST_F(SubjectKeyIdentifierExtensionTest, SetCriticalTest) {
  SetCritical(DefaultConstructor());
}

TEST_F(SubjectKeyIdentifierExtensionTest, GetNameTest) {
  GetName(DefaultConstructor());
}

TEST_F(SubjectKeyIdentifierExtensionTest, GetTypeTest) {
  GetType(DefaultConstructor());
}

TEST_F(SubjectKeyIdentifierExtensionTest, ExtTest) {
  Ext2xml(DefaultConstructor());
}
