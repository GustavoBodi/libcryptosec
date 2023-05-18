#include <libcryptosec/certificate/DistributionPointName.h>

#include <sstream>
#include <gtest/gtest.h>
#include <stdlib.h>

/**
 * @brief Testes unitários da classe DistributionPointName
 */
class DistributionPointNameTest : public ::testing::Test {

protected:
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    DistributionPointName genEmpty() {
      return DistributionPointName();
    }

    DistributionPointName genFullName() {
      DistributionPointName ret;
      GeneralNames gns;
      GeneralName gn;

      gn.setOtherName(fullNameOid, fullNameData);
      gns.addGeneralName(gn);
      gn.setUniformResourceIdentifier(fullNameUri);
      gns.addGeneralName(gn);
      ret.setFullName(gns);

      return ret;
    }

    DistributionPointName genRelativeName() {
      DistributionPointName ret;
      RDNSequence rdn;

      rdn.addEntry(RDNSequence::COMMON_NAME, relativeNameCN);
      rdn.addEntry(RDNSequence::SERIAL_NUMBER, relativeNameSerial);
      ret.setNameRelativeToCrlIssuer(rdn);

      return ret;
    }

    std::vector<DistributionPointName> genAllDistributionPointName() {
      std::vector<DistributionPointName> ret;
      
      ret.push_back(genEmpty());
      ret.push_back(genFullName());
      ret.push_back(genRelativeName());

      return ret;
    }

    std::vector<std::string> genXmls() { 
      std::vector<DistributionPointName> dpns = genAllDistributionPointName();
      std::vector<std::string> ret;
      std::string xml;

      xml = "<distributionPointName>\n";

      for (unsigned int i = 0; i < dpns.size(); i++) {
        DistributionPointName dpn = dpns.at(i);
        DistributionPointName::Type type = dpn.getType();

        xml = "<distributionPointName>\n";
      
        switch (type) {
          case DistributionPointName::FULL_NAME:
            xml += dpn.getFullName().getXmlEncoded("\t");
            break;
          case DistributionPointName::RELATIVE_NAME:
            xml += dpn.getNameRelativeToCrlIssuer().getXmlEncoded("\t");
            break;
          default:
            xml += "\tundefined\n";
            break;
        }

        xml += "</distributionPointName>\n";
        ret.push_back(xml);
      }

      return ret;
    }

    void testFullName(DistributionPointName dpn) {
      RDNSequence rdn = dpn.getNameRelativeToCrlIssuer();
      GeneralNames gns = dpn.getFullName();
      std::vector<GeneralName> gnVector = gns.getGeneralNames();

      ASSERT_EQ(dpn.getType(), DistributionPointName::FULL_NAME);
      ASSERT_EQ(rdn.getEntries().size(), 0);
      ASSERT_EQ(gns.getNumberOfEntries(), 2);
      ASSERT_EQ(gnVector.at(0).getOtherName().first, fullNameOid);
      ASSERT_EQ(gnVector.at(0).getOtherName().second, fullNameData);
      ASSERT_EQ(gnVector.at(1).getUniformResourceIdentifier(), fullNameUri);
    }

    void testRelativeName(DistributionPointName dpn) {
      RDNSequence rdn = dpn.getNameRelativeToCrlIssuer();
      GeneralNames gns = dpn.getFullName();
      
      ASSERT_EQ(dpn.getType(), DistributionPointName::RELATIVE_NAME);
      ASSERT_EQ(gns.getNumberOfEntries(), 0);
      ASSERT_EQ(rdn.getEntries().size(), 2);
      ASSERT_EQ(rdn.getEntries(RDNSequence::COMMON_NAME).at(0), relativeNameCN);
      ASSERT_EQ(rdn.getEntries(RDNSequence::SERIAL_NUMBER).at(0), relativeNameSerial);
    }

    void testEmpty(DistributionPointName dpn) {
      RDNSequence rdn = dpn.getNameRelativeToCrlIssuer();
      GeneralNames gns = dpn.getFullName();
      
      ASSERT_EQ(dpn.getType(), DistributionPointName::UNDEFINED);
      ASSERT_EQ(rdn.getEntries().size(), 0);
      ASSERT_EQ(gns.getNumberOfEntries(), 0);
    }

    void testSanity() {
      DistributionPointName dpn = genEmpty();
      DIST_POINT_NAME *x509 = dpn.getDistPointName();
      DistributionPointName copy(x509);

      testEmpty(copy);

      dpn = genFullName();
      x509 = dpn.getDistPointName();
      copy = DistributionPointName(x509);
      
      testFullName(copy);

      dpn = genRelativeName();
      x509 = dpn.getDistPointName();
      copy = DistributionPointName(x509);

      testRelativeName(copy);
    }

    void testXml() {
      std::vector<DistributionPointName> dpns = genAllDistributionPointName();
      std::vector<std::string> xmls = genXmls();

      for (unsigned int i = 0; i < xmls.size(); i++) {
        ASSERT_EQ(dpns.at(i).getXmlEncoded(), xmls.at(i));
      }
    }

    static std::string fullNameOid;
    static std::string fullNameData;
    static std::string fullNameUri;
    static std::string relativeNameCN;
    static std::string relativeNameSerial;
};

/*
 * Initialization of variables used in the tests
 */
std::string DistributionPointNameTest::fullNameOid = "2.16.76.1.3.3";
std::string DistributionPointNameTest::fullNameData = "00000000000100";
std::string DistributionPointNameTest::fullNameUri = "codigofulano.com";
std::string DistributionPointNameTest::relativeNameCN = "Codigos Fulano";
std::string DistributionPointNameTest::relativeNameSerial = "10203040";

TEST_F(DistributionPointNameTest, Empty) {
  DistributionPointName dpn = genEmpty();
  testEmpty(dpn);
}

TEST_F(DistributionPointNameTest, FullName) {
  DistributionPointName dpn = genFullName();
  testFullName(dpn);
}

TEST_F(DistributionPointNameTest, RelativeName) {
  DistributionPointName dpn = genRelativeName();
  testRelativeName(dpn);
}

TEST_F(DistributionPointNameTest, XMLEncoded) {
  testXml();
}

TEST_F(DistributionPointNameTest, Sanity) {
  testSanity();
}
