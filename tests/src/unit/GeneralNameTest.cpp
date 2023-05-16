#include <libcryptosec/certificate/GeneralName.h>

#include <sstream>
#include <gtest/gtest.h>
#include <stdlib.h>

/**
 * @brief Testes unitários da classe GeneralName
 */
class GeneralNameTest : public ::testing::Test {

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

    std::vector<std::string> genXmls() {
      std::vector<std::string> ret;
      std::vector<std::string> data {"", otherNameData, rfc822Name, dnsName, directoryCN, 
                                 uri, ipAddress, ridOid};

      for (unsigned i = 0; i < typeNames.size(); i++) {
        std::string xml;
        std::string typeName;
        GeneralName::Type type;
        RDNSequence rdn;
        ObjectIdentifier oid;

        type = (GeneralName::Type) i;
        typeName = GeneralName::type2Name(type);
        xml = "<" + typeName + ">\n";

        switch (type) {
          case GeneralName::OTHER_NAME:
            xml += "\t" + otherNameOid + " : " + data.at(i) + "\n";
            break;
          case GeneralName::DIRECTORY_NAME:
            rdn.addEntry(RDNSequence::COMMON_NAME, directoryCN);
            xml += rdn.getXmlEncoded("\t");
            break;
          case GeneralName::REGISTERED_ID:
            oid = ObjectIdentifierFactory::getObjectIdentifier(data.at(i));
            xml += "\t" + oid.getName() + "\n";
            break;
          case GeneralName::UNDEFINED:
            break;
          case GeneralName::RFC_822_NAME:
          case GeneralName::DNS_NAME:
          case GeneralName::UNIFORM_RESOURCE_IDENTIFIER:
          case GeneralName::IP_ADDRESS:
          default:
            xml += "\t" + data.at(i) + "\n";
            break;
        }
        
        xml += "</" + typeName + ">\n";
        ret.push_back(xml);
      }

      return ret;
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

    void testClean() {
      GeneralName gn;
      testEmpty(gn);
     
      gn.setOtherName(otherNameOid, otherNameData);
      testOtherName(gn);
      
      gn.setRfc822Name(rfc822Name);
      testRfc822Name(gn);

      gn.setDnsName(dnsName);
      testDnsName(gn);

      RDNSequence rdn;
      rdn.addEntry(RDNSequence::COMMON_NAME, directoryCN);
      gn.setDirectoryName(rdn);
      testDirectoryName(gn);

      gn.setUniformResourceIdentifier(uri);
      testUniformResourceIdentifier(gn);

      gn.setIpAddress(ipAddress);
      testIpAddress(gn);

      ObjectIdentifier oid = ObjectIdentifierFactory::getObjectIdentifier(ridOid);
      gn.setRegisteredId(oid);
      testRegisteredId(gn);

      gn.setOtherName(otherNameOid, otherNameData);
      testOtherName(gn);
    }

    void testSanity() {
      std::vector<GeneralName> gns = genAllNames();
      GeneralName gnSanity;
      GENERAL_NAME *x509;

      for (unsigned int i = 0; i < gns.size(); i++) {
        x509 = gns.at(i).getGeneralName();
        gnSanity = GeneralName(x509);

        // XML Encoded assures both the type and data are the same,
        // however this relies on XML Encoded Test working
        ASSERT_EQ(gnSanity.getXmlEncoded(), gns.at(i).getXmlEncoded());
      }
    }

    void testAssignment() {
      std::vector<GeneralName> gns = genAllNames();
      GeneralName gnAssign;

      for (unsigned int i = 0; i < gns.size(); i++) {
        gnAssign = gns.at(i);

        // XML Encoded assures both the type and data are the same,
        // however this relies on XML Encoded Test working
        ASSERT_EQ(gnAssign.getXmlEncoded(), gns.at(i).getXmlEncoded());
      }
    }

    void testType2Name() {
      for (unsigned int i = 0; i < typeNames.size(); i++) {
        GeneralName::Type type = (GeneralName::Type) i;

        ASSERT_EQ(GeneralName::type2Name(type), typeNames.at(i));
      }
    }

    void testXml() {
      std::vector<std::string> xmls = genXmls();
      std::vector<GeneralName> gns = genAllNames();

      for (unsigned int i = 0; i < xmls.size(); i++) {
        ASSERT_EQ(gns.at(i).getXmlEncoded(), xmls.at(i));
      }
    }

    void testData2IpAddress() {
      unsigned char *data = (unsigned char *) calloc(5, sizeof(unsigned char));

      // Make sure the number is the same as IP address
      data[0] = atoi("127") & 0x00FF;
      data[1] = atoi("0") & 0x00FF;
      data[2] = atoi("0") & 0x00FF;
      data[3] = atoi("1") & 0x00FF;
      data[4] = '\0';

      ASSERT_EQ(GeneralName::data2IpAddress(data), ipAddress);
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
std::string GeneralNameTest::otherNameOid = "2.16.76.1.3.3";
std::string GeneralNameTest::otherNameData = "00000000000100";
std::string GeneralNameTest::rfc822Name = "example@mail.com";
std::string GeneralNameTest::dnsName = "8.8.8.8";
std::string GeneralNameTest::directoryCN = "Example Name";
std::string GeneralNameTest::uri = "www.example.com";
std::string GeneralNameTest::ipAddress = "127.0.0.1";
std::string GeneralNameTest::ridOid = "2.5.4.3";

std::vector<std::string> GeneralNameTest::typeNames {"undefined", "otherName", "rfc822Name", "dnsName", "directoryName",
                                    "uniformResourceIdentifier", "iPAddress", "registeredID"};

TEST_F(GeneralNameTest, Empty) {
  GeneralName gn = genEmpty();
  testEmpty(gn);
}

/**
 * @brief Tests GeneralName Other Name funcionalities
 */
TEST_F(GeneralNameTest, OtherName) {
  GeneralName gn = genOtherName();
  testOtherName(gn);
}

/**
 * @brief Tests Generalname RFC 822 Name functionalities
 */
TEST_F(GeneralNameTest, Rfc822Name) {
  GeneralName gn = genRfc822Name();
  testRfc822Name(gn);
}

/**
 * @brief Tests GeneralName DNS Name functionalities
 */
TEST_F(GeneralNameTest, DnsName) {
  GeneralName gn = genDnsName();
  testDnsName(gn);
}

/**
 * @brief Tests GeneralName Directory Name functionalities
 */
TEST_F(GeneralNameTest, DirectoryName) {
  GeneralName gn = genDirectoryName();
  testDirectoryName(gn);
}

/**
 * @brief Tests General Name Uniform Resource Identifier functionalities
 */
TEST_F(GeneralNameTest, UniformResourceIdentifier) {
  GeneralName gn = genUniformResourceIdentifier();
  testUniformResourceIdentifier(gn);
}

/**
 * @brief Tests General Name IP Address functionalities
 */
TEST_F(GeneralNameTest, IPAddress) {
  GeneralName gn = genIpAddress();
  testIpAddress(gn);
}

/**
 * @brief Tests General Name Registered ID functionalities
 */
TEST_F(GeneralNameTest, RegisteredID) {
  GeneralName gn = genRegisteredId();
  testRegisteredId(gn);
}

TEST_F(GeneralNameTest, Clean) {
  testClean();
}

TEST_F(GeneralNameTest, Type2Name) {
  testType2Name();
}

TEST_F(GeneralNameTest, XmlEncoded) {
  testXml();
}

TEST_F(GeneralNameTest, Data2IpAddress) {
  testData2IpAddress();
}

TEST_F(GeneralNameTest, Assignment) {
  testAssignment();
}

TEST_F(GeneralNameTest, SanityTest) {
  testSanity();
}
