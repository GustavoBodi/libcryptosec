#include <libcryptosec/certificate/GeneralNames.h>

#include <sstream>
#include <gtest/gtest.h>
#include <stdlib.h>

/**
 * @brief Testes unitários da classe GeneralNames
 */
class GeneralNamesTest : public ::testing::Test {

protected:
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    GeneralName genEmpty() {
      GeneralName gn;
      return gn;
    }

    GeneralName genOtherName() {
      GeneralName gn;
      gn.setOtherName(otherNameOid, otherNameData);
      return gn;
    }

    GeneralName genRfc822Name() {
      GeneralName gn;
      gn.setRfc822Name(rfc822Name);
      return gn;
    }

    GeneralName genDnsName() {
      GeneralName gn;
      gn.setDnsName(dnsName);
      return gn;
    }

    GeneralName genDirectoryName() {
      GeneralName gn;
      RDNSequence rdn;

      rdn.addEntry(RDNSequence::COMMON_NAME, directoryCN);
      gn.setDirectoryName(rdn);

      return gn;
    }

    GeneralName genUniformResourceIdentifier() {
      GeneralName gn;
      gn.setUniformResourceIdentifier(uri);
      return gn;
    }

    GeneralName genIpAddress() {
      GeneralName gn;
      gn.setIpAddress(ipAddress);
      return gn;
    }

    GeneralName genRegisteredId() {
      GeneralName gn;
      ObjectIdentifier oid;

      oid = ObjectIdentifierFactory::getObjectIdentifier(ridOid);
      gn.setRegisteredId(oid);

      return gn;
    }

    std::vector<GeneralName> genAllNames() {
      std::vector<GeneralName> gns;
      gns.push_back(genEmpty());
      gns.push_back(genOtherName());
      gns.push_back(genRfc822Name());
      gns.push_back(genDnsName());
      gns.push_back(genDirectoryName());
      gns.push_back(genUniformResourceIdentifier());
      gns.push_back(genIpAddress());
      gns.push_back(genRegisteredId());

      return gns;
    }

    GeneralNames genGeneralNames() {
      std::vector<GeneralName> gns = genAllNames();
      GeneralNames ret;

      for (unsigned int i = 0; i < gns.size(); i++) {
        ret.addGeneralName(gns.at(i));
      }

      return ret;
    }

    std::string genGeneralNamesXml() {
      std::vector<GeneralName> gns = genGeneralNames().getGeneralNames();
      std::string generalNamesXml;

      generalNamesXml = "<generalNames>\n";

      for (unsigned int i = 0; i < gns.size(); i++) {
        generalNamesXml += gns.at(i).getXmlEncoded("\t");
      }

      generalNamesXml += "</generalNames>\n";

      return generalNamesXml;
    }

    void testEmpty(GeneralName gn) {
      ASSERT_EQ(gn.getType(), GeneralName::UNDEFINED);
    }

    void testOtherName(GeneralName gn) {
      std::pair<std::string, std::string> otherName;

      otherName = gn.getOtherName();

      ASSERT_EQ(otherName.first, otherNameOid);
      ASSERT_EQ(otherName.second, otherNameData);
      ASSERT_EQ(gn.getType(), GeneralName::OTHER_NAME);
    }

    void testRfc822Name(GeneralName gn) {
      ASSERT_EQ(gn.getRfc822Name(), rfc822Name);
      ASSERT_EQ(gn.getType(), GeneralName::RFC_822_NAME);
    }
    
    void testDnsName(GeneralName gn) {
      ASSERT_EQ(gn.getDnsName(), dnsName);
      ASSERT_EQ(gn.getType(), GeneralName::DNS_NAME);
    }

    void testDirectoryName(GeneralName gn) {
      RDNSequence rdn;
      std::string directoryName;

      rdn = gn.getDirectoryName();
      directoryName = rdn.getEntries(RDNSequence::COMMON_NAME).at(0);

      ASSERT_EQ(directoryName, directoryCN);
      ASSERT_EQ(gn.getType(), GeneralName::DIRECTORY_NAME);
    }

    void testUniformResourceIdentifier(GeneralName gn) {
      ASSERT_EQ(gn.getUniformResourceIdentifier(), uri);
      ASSERT_EQ(gn.getType(), GeneralName::UNIFORM_RESOURCE_IDENTIFIER);
    }

    void testIpAddress(GeneralName gn) {
      ASSERT_EQ(gn.getIpAddress(), ipAddress);
      ASSERT_EQ(gn.getType(), GeneralName::IP_ADDRESS);
    }

    void testRegisteredId(GeneralName gn) {
      ObjectIdentifier oid;

      oid = gn.getRegisteredId();

      ASSERT_EQ(oid.getOid(), ridOid);
      ASSERT_EQ(gn.getType(), GeneralName::REGISTERED_ID);
    }

    void testGeneralNames(GeneralNames generalNames) {
      std::vector<GeneralName> gns = generalNames.getGeneralNames();

      for (unsigned int i = 0; i < gns.size(); i++) {
        switch (gns.at(i).getType()) {
          case GeneralName::OTHER_NAME:
            testOtherName(gns.at(i));
            break;
          case GeneralName::RFC_822_NAME:
            testRfc822Name(gns.at(i));
            break;
          case GeneralName::DNS_NAME:
            testDnsName(gns.at(i));
            break;
          case GeneralName::DIRECTORY_NAME:
            testDirectoryName(gns.at(i));
            break;
          case GeneralName::UNIFORM_RESOURCE_IDENTIFIER:
            testUniformResourceIdentifier(gns.at(i));
            break;
          case GeneralName::IP_ADDRESS:
            testIpAddress(gns.at(i));
            break;
          case GeneralName::REGISTERED_ID:
            testRegisteredId(gns.at(i));
            break;
          default:
            testEmpty(gns.at(i));
            break;
        }
      }
    }

    void testXml(GeneralNames generalNames) {
      std::string xml = genGeneralNamesXml();
      ASSERT_EQ(generalNames.getXmlEncoded(), xml);
    }

    void testNumberOfEntries(GeneralNames generalNames) {
      std::vector<GeneralName> gns = genAllNames();
      ASSERT_EQ(generalNames.getNumberOfEntries(), gns.size());
    }

    void testAssignment(GeneralNames generalNames) {
      GeneralNames gns = generalNames;
      testGeneralNames(gns);
    }

    void testSanity(GeneralNames generalNames) {
      GENERAL_NAMES *x509 = generalNames.getInternalGeneralNames();
      GeneralNames sanity(x509);
      testGeneralNames(sanity);
    }

    static std::string otherNameOid;
    static std::string otherNameData;
    static std::string rfc822Name;
    static std::string dnsName;
    static std::string directoryCN;
    static std::string uri;
    static std::string ipAddress;
    static std::string ridOid;
    static std::vector<std::string> typeNames;
};

/*
 * Initialization of variables used in the tests
 */
std::string GeneralNamesTest::otherNameOid = "2.16.76.1.3.3";
std::string GeneralNamesTest::otherNameData = "00000000000100";
std::string GeneralNamesTest::rfc822Name = "example@mail.com";
std::string GeneralNamesTest::dnsName = "8.8.8.8";
std::string GeneralNamesTest::directoryCN = "Example Name";
std::string GeneralNamesTest::uri = "www.example.com";
std::string GeneralNamesTest::ipAddress = "127.0.0.1";
std::string GeneralNamesTest::ridOid = "2.5.4.3";

TEST_F(GeneralNamesTest, AddGeneralName) {
  GeneralNames gns = genGeneralNames();
  testGeneralNames(gns);
}

TEST_F(GeneralNamesTest, NumberOfEntries) {
  GeneralNames gns = genGeneralNames();
  testNumberOfEntries(gns);
}

TEST_F(GeneralNamesTest, GetXML) {
  GeneralNames gns = genGeneralNames();
  testXml(gns);
}

TEST_F(GeneralNamesTest, Assignment) {
  GeneralNames gns = genGeneralNames();
  testAssignment(gns);
}

TEST_F(GeneralNamesTest, Sanity) {
  GeneralNames gns = genGeneralNames();
  testSanity(gns);
}
