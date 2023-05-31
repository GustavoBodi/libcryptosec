#include <libcryptosec/certificate/AuthorityInformationAccessExtension.h>
#include <libcryptosec/certificate/ObjectIdentifierFactory.h>

#include <sstream>
#include <gtest/gtest.h>
#include <stdlib.h>

/**
 * @brief Testes unitários da classe AuthorityInformationAccessExtension
 */
class AuthorityInformationAccessExtensionTest : public ::testing::Test {

protected:
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    AccessDescription genAccessDescription(int i = 0) {
      ObjectIdentifier obj = ObjectIdentifierFactory::getObjectIdentifier(oid);
      GeneralName gn;
      AccessDescription ret;

      if (i) {
        gn.setUniformResourceIdentifier(uri);
      } else {
        gn.setDnsName(dns);
      }

      ret.setAccessLocation(gn);
      ret.setAccessMethod(obj);

      return ret;
    }

    AuthorityInformationAccessExtension genEmpty() {
      return AuthorityInformationAccessExtension();
    }

    AuthorityInformationAccessExtension genAIA() {
      AuthorityInformationAccessExtension ret;
      AccessDescription ad;

      ad = genAccessDescription(0);
      ret.addAccessDescription(ad);
      
      ad = genAccessDescription(1);
      ret.addAccessDescription(ad);

      return ret;
    }

    std::vector<AuthorityInformationAccessExtension> genAIAs() {
      std::vector<AuthorityInformationAccessExtension> ret;

      ret.push_back(genEmpty());
      ret.push_back(genAIA());

      return ret;
    }

    std::vector<std::string> genValue2Xmls(std::string tab = "") {
      std::vector<std::string> ret;
      
      for (unsigned int i = 0; i < 2; i++) {
        std::string xml = tab + "<accessDescriptions>\n";

        if (i) {
          xml += genAccessDescription(0).getXmlEncoded(tab + "\t"); 
          xml += genAccessDescription(1).getXmlEncoded(tab + "\t"); 
        }

        xml += tab + "</accessDescriptions>\n";
        ret.push_back(xml);
      }

      return ret;
    }

    std::vector<std::string> genXmls(std::string tab = "") {
      std::vector<std::string> ret;
      std::vector<std::string> value2Xmls = genValue2Xmls("\t\t");

      for (unsigned int i = 0; i < 2; i++) {
        std::string xml = tab + "<authorityInformationAccess>\n";
        xml += tab + "\t<extnID>authorityInfoAccess</extnID>\n";
        xml += tab + "\t<critical>no</critical>\n";
        xml += tab + "\t<extnValue>\n";
        xml += value2Xmls.at(i);
        xml += tab + "\t</extnValue>\n";
        xml += tab + "</authorityInformationAccess>\n";

        ret.push_back(xml);
      }

      return ret;
    }

    void testEmpty(AuthorityInformationAccessExtension ext) {
      std::vector<AccessDescription> ads = ext.getAccessDescriptions();

      ASSERT_EQ(ads.size(), 0);
    }

    void testAIA(AuthorityInformationAccessExtension ext) {
      std::vector<AccessDescription> ads = ext.getAccessDescriptions();
      AccessDescription ad;

      ASSERT_EQ(ads.size(), 2);

      ad = ads.at(0);
      ASSERT_EQ(ad.getAccessMethod().getOid(), oid);
      ASSERT_EQ(ad.getAccessMethod().getName(), name);
      ASSERT_EQ(ad.getAccessLocation().getDnsName(), dns);

      ad = ads.at(1);
      ASSERT_EQ(ad.getAccessMethod().getOid(), oid);
      ASSERT_EQ(ad.getAccessMethod().getName(), name);
      ASSERT_EQ(ad.getAccessLocation().getUniformResourceIdentifier(), uri);
    }
   
    void testSanity() {
      AuthorityInformationAccessExtension aia;
      X509_EXTENSION *ext = aia.getX509Extension();
      AuthorityInformationAccessExtension copy(ext);

      testEmpty(copy);

      aia = genAIA();
      ext = aia.getX509Extension();
      copy = AuthorityInformationAccessExtension(ext);

      testAIA(aia);
    }

    void testValue2Xml() {
      std::vector<AuthorityInformationAccessExtension> aias = genAIAs();
      std::vector<std::string> xmls = genValue2Xmls();

      for (unsigned int i = 0; i < aias.size(); i++) {
        ASSERT_EQ(aias.at(i).extValue2Xml(), xmls.at(i));
      }
    }

    void testXml() {
      std::vector<AuthorityInformationAccessExtension> aias = genAIAs();
      std::vector<std::string> xmls = genXmls();

      for (unsigned int i = 0; i < aias.size(); i++) {
        ASSERT_EQ(aias.at(i).getXmlEncoded(), xmls.at(i));
      }
    }

    static std::string oid;
    static std::string name;
    static std::string uri;
    static std::string dns;
};

/*
 * Initialization of variables used in the tests
 */
std::string AuthorityInformationAccessExtensionTest::oid = "1.3.6.1.5.5.7.1.1";
std::string AuthorityInformationAccessExtensionTest::name = "authorityInfoAccess";
std::string AuthorityInformationAccessExtensionTest::uri = "www.example.com";
std::string AuthorityInformationAccessExtensionTest::dns = "8.8.8.8";

TEST_F(AuthorityInformationAccessExtensionTest, Empty) {
  AuthorityInformationAccessExtension ext = genEmpty();
  testEmpty(ext);
}

TEST_F(AuthorityInformationAccessExtensionTest, GetAccessDescription) {
  AuthorityInformationAccessExtension ext = genAIA();
  testAIA(ext);
}

TEST_F(AuthorityInformationAccessExtensionTest, Sanity) {
  testSanity();
}

TEST_F(AuthorityInformationAccessExtensionTest, Value2XML) {
  testValue2Xml();
}

TEST_F(AuthorityInformationAccessExtensionTest, XMLEncoded) {
  testXml();
}
