#include <libcryptosec/certificate/AccessDescription.h>
#include <libcryptosec/certificate/ObjectIdentifierFactory.h>

#include <sstream>
#include <gtest/gtest.h>
#include <stdlib.h>

/**
 * @brief Testes unitários da classe AccessDescription
 */
class AccessDescriptionTest : public ::testing::Test {

protected:
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    GeneralName genEmptyGN() {
      return GeneralName();
    }

    GeneralName genRfc822NameGN() {
      GeneralName gn;
      gn.setRfc822Name(rfc822Name);
      return gn;
    }
    
    ObjectIdentifier genEmptyOid() {
      return ObjectIdentifier();
    }
    
    ObjectIdentifier genOid() {
      return ObjectIdentifierFactory::getObjectIdentifier(oid);
    }

    AccessDescription genEmpty() {
      return AccessDescription();
    }

    AccessDescription genAccessDescription() {
      GeneralName gn = genRfc822NameGN();
      ObjectIdentifier obj = genOid();
      AccessDescription ad;

      ad.setAccessLocation(gn);
      ad.setAccessMethod(obj);

      return ad;
    }

    std::vector<AccessDescription> genAllAccessDescription() {
      std::vector<AccessDescription> ret;

      ret.push_back(genEmpty());
      ret.push_back(genAccessDescription());

      return ret;
    }

    std::vector<std::string> genXml() {
      std::vector<AccessDescription> ads = genAllAccessDescription();
      std::vector<std::string> ret;

      for (unsigned int i = 0; i < ads.size(); i++) {
        std::string xml = "<accessDescription>\n";
        xml += ads.at(i).getAccessMethod().getXmlEncoded("\t");
        xml += ads.at(i).getAccessLocation().getXmlEncoded("\t");
        xml += "</accessDescription>\n";

        ret.push_back(xml);
      }

      return ret;
    }

    void testEmptyGN(GeneralName gn) {
      ASSERT_EQ(gn.getType(), GeneralName::UNDEFINED);
    }

    void testRfc822NameGN(GeneralName gn) {
      ASSERT_EQ(gn.getRfc822Name(), rfc822Name);
      ASSERT_EQ(gn.getType(), GeneralName::RFC_822_NAME);
    }

    void testEmptyOid(ObjectIdentifier obj) {
      ASSERT_THROW(obj.getOid(), CertificationException);
      ASSERT_EQ(obj.getNid(), NID_undef);
      ASSERT_EQ(obj.getName(), nameEmpty);
    }

    void testOid(ObjectIdentifier obj) {
      ASSERT_EQ(obj.getOid(), oid);
      ASSERT_EQ(obj.getNid(), nid);
      ASSERT_EQ(obj.getName(), name);
    }
    
    void testAccessLocationEmpty(AccessDescription ad) { 
      GeneralName gn = ad.getAccessLocation();
      testEmptyGN(gn);
    }

    void testAccessLocation(AccessDescription ad) { 
      GeneralName gn = ad.getAccessLocation();
      testRfc822NameGN(gn);
    }

    void testAccessMethodEmpty(AccessDescription ad) {
      ObjectIdentifier obj = ad.getAccessMethod();
      testEmptyOid(obj);
    }

    void testAccessMethod(AccessDescription ad) {
      ObjectIdentifier obj = ad.getAccessMethod();
      testOid(obj);
    }

    void testEmpty(AccessDescription ad) {
      testAccessLocationEmpty(ad);
      testAccessMethodEmpty(ad);
    }

    void testAccessDescription(AccessDescription ad) { 
      testAccessLocation(ad);
      testAccessMethod(ad);
    }

    void testSanity() {
      AccessDescription ad = genEmpty();
      ACCESS_DESCRIPTION *x509 = ad.getAccessDescription();
      AccessDescription copy = AccessDescription(x509);

      testEmpty(copy);

      ad = genAccessDescription();
      x509 = ad.getAccessDescription();
      copy = AccessDescription(x509);

      testAccessDescription(copy);
    }

    void testXml() {
      std::vector<std::string> xmls = genXml();
      std::vector<AccessDescription> ads = genAllAccessDescription();

      for (unsigned int i = 0; i < ads.size(); i++ ) {
        ASSERT_EQ(ads.at(i).getXmlEncoded(), xmls.at(i));
      }
    }

    static int nid;
    static std::string rfc822Name;
    static std::string oid;
    static std::string name;
    static std::string nameEmpty; 
};

/*
 * Initialization of variables used in the tests
 */
int AccessDescriptionTest::nid = NID_sinfo_access;
std::string AccessDescriptionTest::rfc822Name = "example@mail.com";
std::string AccessDescriptionTest::oid = "1.3.6.1.5.5.7.1.11";
std::string AccessDescriptionTest::name = "subjectInfoAccess";
std::string AccessDescriptionTest::nameEmpty = "undefined";

TEST_F(AccessDescriptionTest, AccessLocationEmpty) {
  AccessDescription ad = genEmpty();
  testAccessLocationEmpty(ad);
}

TEST_F(AccessDescriptionTest, AccessMethodEmpty) {
  AccessDescription ad = genEmpty();
  testAccessMethodEmpty(ad);
}

TEST_F(AccessDescriptionTest, AccessLocation) {
  AccessDescription ad = genAccessDescription();
  testAccessLocation(ad);
}

TEST_F(AccessDescriptionTest, AccessMethod) {
  AccessDescription ad = genAccessDescription();
  testAccessMethod(ad);
}

TEST_F(AccessDescriptionTest, Sanity) {
  testSanity();
}

TEST_F(AccessDescriptionTest, XMLEncoded) {
  testXml();
}

