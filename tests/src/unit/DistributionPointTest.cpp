
#include <libcryptosec/certificate/DistributionPoint.h>

#include <sstream>
#include <gtest/gtest.h>
#include <stdlib.h>

/**
 * @brief Testes unitários da classe DistributionPoint
 */
class DistributionPointTest : public ::testing::Test {

protected:
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    DistributionPointName genFullNameDPN() {
      DistributionPointName ret;
      GeneralNames gns;
      GeneralName gn;

      gn.setOtherName(gnOid, fullNameData);
      gns.addGeneralName(gn);
      gn.setUniformResourceIdentifier(fullNameUri);
      gns.addGeneralName(gn);
      ret.setFullName(gns);

      return ret;
    }

    DistributionPointName genRelativeNameDPN() {
      DistributionPointName ret;
      RDNSequence rdn;

      rdn.addEntry(RDNSequence::COMMON_NAME, relativeNameCN);
      rdn.addEntry(RDNSequence::SERIAL_NUMBER, relativeNameSerial);
      ret.setNameRelativeToCrlIssuer(rdn);

      return ret;
    }

    GeneralNames genCrlIssuer() {
      GeneralNames gns;
      GeneralName gn;

      gn.setOtherName(gnOid, crlData);
      gns.addGeneralName(gn);
      gn.setUniformResourceIdentifier(crlUri);
      gns.addGeneralName(gn);
    
      return gns;
    }

    DistributionPoint genDistributionPointEmpty() {
      return DistributionPoint();
    }

    DistributionPoint genDistributionPointFull() {
      DistributionPointName dpn = genFullNameDPN();
      GeneralNames crlIssuer = genCrlIssuer();
      DistributionPoint ret;

      ret.setDistributionPointName(dpn);
      ret.setCrlIssuer(crlIssuer);

      for (unsigned int i = 0; i < reasons.size(); i++) {
        ret.setReasonFlag((DistributionPoint::ReasonFlags) i, reasons.at(i));
      }

      return ret;
    }

    DistributionPoint genDistributionPointRelative() {
      DistributionPointName dpn = genRelativeNameDPN();
      GeneralNames crlIssuer = genCrlIssuer();
      DistributionPoint ret;

      ret.setDistributionPointName(dpn);
      ret.setCrlIssuer(crlIssuer);

      for (unsigned int i = 0; i < reasons.size(); i++) {
        ret.setReasonFlag((DistributionPoint::ReasonFlags) i, !reasons.at(i));
      }

      return ret;
    }

    std::vector<DistributionPoint> genAllDistributionPoint() {
      std::vector<DistributionPoint> ret;
      
      ret.push_back(genDistributionPointEmpty());
      ret.push_back(genDistributionPointFull());
      ret.push_back(genDistributionPointRelative());

      return ret;
    }

    std::vector<std::string> genXml() {
      std::vector<DistributionPoint> dps = genAllDistributionPoint();
      std::vector<std::string> ret;

      for (unsigned int i = 0; i < dps.size(); i++) {
        std::string xml = "<distributionPoint>\n";

        if (dps.at(i).getDistributionPointName().getType() != DistributionPointName::UNDEFINED) {
          xml += dps.at(i).getDistributionPointName().getXmlEncoded("\t");
        }

        xml += "\t<reasonFlag>\n";

        for (unsigned int j = 0; j < 7; j++) {
          std::string reason = reasonNames.at(j);
          std::string value;
          
          switch (dps.at(i).getDistributionPointName().getType()) {
            case DistributionPointName::FULL_NAME:
              value = this->reasons[j]?"1":"0";
              break;
            case DistributionPointName::RELATIVE_NAME:
              value = this->reasons[j]?"0":"1";
              break;
            default:
              value = "0";
              break;
          }

          xml += "\t\t<" + reason + ">" + value + "</" + reason + ">\n";
        }

        xml += "\t</reasonFlag>\n";

        if (dps.at(i).getCrlIssuer().getNumberOfEntries()) {
          xml += dps.at(i).getCrlIssuer().getXmlEncoded("\t");
        }

        xml += "</distributionPoint>\n";

        ret.push_back(xml);
      }

      return ret;
    }

    void testFullNameDPN(DistributionPointName dpn) {
      RDNSequence rdn = dpn.getNameRelativeToCrlIssuer();
      GeneralNames gns = dpn.getFullName();
      std::vector<GeneralName> gnVector = gns.getGeneralNames();

      ASSERT_EQ(dpn.getType(), DistributionPointName::FULL_NAME);
      ASSERT_EQ(rdn.getEntries().size(), 0);
      ASSERT_EQ(gns.getNumberOfEntries(), 2);
      ASSERT_EQ(gnVector.at(0).getOtherName().first, gnOid);
      ASSERT_EQ(gnVector.at(0).getOtherName().second, fullNameData);
      ASSERT_EQ(gnVector.at(1).getUniformResourceIdentifier(), fullNameUri);
    }

    void testRelativeNameDPN(DistributionPointName dpn) {
      RDNSequence rdn = dpn.getNameRelativeToCrlIssuer();
      GeneralNames gns = dpn.getFullName();
      
      ASSERT_EQ(dpn.getType(), DistributionPointName::RELATIVE_NAME);
      ASSERT_EQ(gns.getNumberOfEntries(), 0);
      ASSERT_EQ(rdn.getEntries().size(), 2);
      ASSERT_EQ(rdn.getEntries(RDNSequence::COMMON_NAME).at(0), relativeNameCN);
      ASSERT_EQ(rdn.getEntries(RDNSequence::SERIAL_NUMBER).at(0), relativeNameSerial);
    }
    
    void testEmptyDPN(DistributionPointName dpn) {
      RDNSequence rdn = dpn.getNameRelativeToCrlIssuer();
      GeneralNames gns = dpn.getFullName();
      
      ASSERT_EQ(dpn.getType(), DistributionPointName::UNDEFINED);
      ASSERT_EQ(rdn.getEntries().size(), 0);
      ASSERT_EQ(gns.getNumberOfEntries(), 0);
    }
   
    void testCrlIssuer(GeneralNames gns) {
      std::vector<GeneralName> gnVector = gns.getGeneralNames();

      ASSERT_EQ(gnVector.size(), 2);
      ASSERT_EQ(gnVector.at(0).getOtherName().first, gnOid);
      ASSERT_EQ(gnVector.at(0).getOtherName().second, crlData);
      ASSERT_EQ(gnVector.at(1).getUniformResourceIdentifier(), crlUri);
    }

    void testDistributionPointFull(DistributionPoint dp) {
      DistributionPointName dpn = dp.getDistributionPointName();
      GeneralNames crlIssuer = dp.getCrlIssuer();

      testFullNameDPN(dpn);
      testCrlIssuer(crlIssuer);

      for (unsigned int i = 0; i < reasons.size(); i++) {
        ASSERT_EQ(dp.getReasonFlag((DistributionPoint::ReasonFlags) i), reasons.at(i));
      }
    }

    void testDistributionPointRelative(DistributionPoint dp) {
      DistributionPointName dpn = dp.getDistributionPointName();
      GeneralNames crlIssuer = dp.getCrlIssuer();

      testRelativeNameDPN(dpn);
      testCrlIssuer(crlIssuer);

      for (unsigned int i = 0; i < reasons.size(); i++) {
        ASSERT_EQ(dp.getReasonFlag((DistributionPoint::ReasonFlags) i), !reasons.at(i));
      }
    }

    void testDistributionPointEmpty(DistributionPoint dp) {
      DistributionPointName dpn = dp.getDistributionPointName();
      GeneralNames crlIssuer = dp.getCrlIssuer();
    
      RDNSequence rdn = dpn.getNameRelativeToCrlIssuer();
      GeneralNames gns = dpn.getFullName();

      ASSERT_EQ(rdn.getEntries().size(), 0);
      ASSERT_EQ(gns.getNumberOfEntries(), 0);
      ASSERT_EQ(crlIssuer.getNumberOfEntries(), 0);

      for (unsigned int i = 0; i < reasons.size(); i++) {
        ASSERT_EQ(dp.getReasonFlag((DistributionPoint::ReasonFlags) i), false);
      }
    }

    void testSanity() {
      std::vector<DistributionPoint> dps = genAllDistributionPoint();

      for (unsigned int i = 0; i < dps.size(); i++) {
        DIST_POINT *x509 = dps.at(i).getDistPoint();
        DistributionPoint copy(x509);

        switch (i) {
          case 0:
            testDistributionPointEmpty(copy);
            break;
          case 1:
            testDistributionPointFull(copy);
            break;
          default:
            testDistributionPointRelative(copy);
            break;
        }
      }
    }

    void testReasonFlag2Name() {
      for (unsigned int i = 0; i < reasonNames.size(); i++) {
        DistributionPoint::ReasonFlags reason = (DistributionPoint::ReasonFlags) i;
        ASSERT_EQ(DistributionPoint::reasonFlag2Name(reason), reasonNames.at(i));
      }
    }

    void testXml() { 
      std::vector<DistributionPoint> dps = genAllDistributionPoint();
      std::vector<std::string> xmls = genXml();

      for (unsigned int i = 0; i < dps.size(); i++) {
        ASSERT_EQ(dps.at(i).getXmlEncoded(), xmls.at(i));
      }
    }

    static std::string gnOid;
    static std::string fullNameData;
    static std::string fullNameUri;
    static std::string relativeNameCN;
    static std::string relativeNameSerial;
    static std::string crlData;
    static std::string crlUri;
    static std::vector<bool> reasons;
    static std::vector<std::string> reasonNames;
};

/*
 * Initialization of variables used in the tests
 */
std::string DistributionPointTest::gnOid = "2.16.76.1.3.3";
std::string DistributionPointTest::fullNameData = "00000000000100";
std::string DistributionPointTest::fullNameUri = "codigofulano.com";
std::string DistributionPointTest::relativeNameCN = "Codigos Fulano";
std::string DistributionPointTest::relativeNameSerial = "10203040";

std::string DistributionPointTest::crlData = "00000000000200";
std::string DistributionPointTest::crlUri = "crlissuer.com";

std::vector<bool> DistributionPointTest::reasons {true, false, false, true, false, true, true};
std::vector<std::string> DistributionPointTest::reasonNames {"unused", "keyCompromise", "caCompromise", "affiliationChanged",
                                                             "superseded", "cessationOfOperation", "certificateHold"};

TEST_F(DistributionPointTest, Empty) {
  DistributionPoint dp = genDistributionPointEmpty();
  testDistributionPointEmpty(dp);
}

TEST_F(DistributionPointTest, FullName) {
  DistributionPoint dp = genDistributionPointFull();
  testDistributionPointFull(dp);
}

TEST_F(DistributionPointTest, RelativeName) {
  DistributionPoint dp = genDistributionPointRelative();
  testDistributionPointRelative(dp);
}

TEST_F(DistributionPointTest, Sanity) {
  testSanity();
}

TEST_F(DistributionPointTest, ReasonFlag2Name) {
  testReasonFlag2Name();
}

TEST_F(DistributionPointTest, XMLEncoded) {
  testXml();
}
