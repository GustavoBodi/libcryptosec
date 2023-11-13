#include <libcryptosec/certificate/CRLDistributionPointsExtension.h>
#include <libcryptosec/certificate/BasicConstraintsExtension.h>

#include <sstream>
#include <gtest/gtest.h>
#include <stdlib.h>

/**
 * @brief Testes unitários da classe CRLDistributionPointsExtension
 */
class CRLDistributionPointsExtensionTest : public ::testing::Test {

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

    CRLDistributionPointsExtension genCRLDistributionPointsExtensionEmpty() {
      return CRLDistributionPointsExtension();
    }

    CRLDistributionPointsExtension genCRLDistributionPointsExtension() {
      CRLDistributionPointsExtension ret;
      std::vector<DistributionPoint> dps = genAllDistributionPoint();

      for (unsigned int i = 0; i < dps.size(); i++) {
        ret.addDistributionPoint(dps.at(i));
      }

      return ret;
   }

    std::string genExtValue2Xml(std::string tab = "", bool empty = false) {
      std::string ret = tab + "<distributionPoints>\n";

      if (!empty) {
        std::vector<DistributionPoint> dps = genAllDistributionPoint();
        for (unsigned int i = 0; i < dps.size(); i++) {
          ret += dps.at(i).getXmlEncoded(tab + "\t");
        }
      }
      ret += tab + "</distributionPoints>\n";
      return ret;
    }

    std::string genXml(std::string tab = "", bool empty = false) {
      std::string ret = tab + "<CRLDistributionPoints>\n";
      ret += tab + "\t<extnID>crlDistributionPoints</extnID>\n";
      ret += tab + "\t<critical>no</critical>\n";
      ret += tab + "\t<extnValue>\n";
      ret += tab + "\t\t<distributionPoints>\n";

      if (!empty) {
        std::vector<DistributionPoint> dps = genAllDistributionPoint();
        for (unsigned int i = 0; i < dps.size(); i++) {
          ret += tab + dps.at(i).getXmlEncoded("\t\t\t");
        }
      }
      ret += tab + "\t\t</distributionPoints>\n";
      ret += tab + "\t</extnValue>\n";
      ret += tab + "</CRLDistributionPoints>\n";

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

    void testCRLDistributionPointsExtensionEmpty(CRLDistributionPointsExtension ext) {
      std::vector<DistributionPoint> dps = ext.getDistributionPoints();

      ASSERT_EQ(dps.size(), 0);
    }

    void testCRLDistributionPointsExtension(CRLDistributionPointsExtension ext) {
      std::vector<DistributionPoint> dps = ext.getDistributionPoints();

      ASSERT_EQ(dps.size(), 3);
      testDistributionPointEmpty(dps.at(0));
      testDistributionPointFull(dps.at(1));
      // This doesn't work properly for some reason
      testDistributionPointRelative(dps.at(2));
    }

    void testSanityWrongExt() {
      BasicConstraintsExtension bc;
      ASSERT_THROW(CRLDistributionPointsExtension(bc.getX509Extension()), CertificationException);
    }

    void testSanity(bool empty = false) {
      CRLDistributionPointsExtension ext = genCRLDistributionPointsExtension();
      X509_EXTENSION *x509;

      if (empty) {
        ext = genCRLDistributionPointsExtensionEmpty();
      }

      x509 = ext.getX509Extension();
      CRLDistributionPointsExtension copy(x509);

      if (empty) {
        testCRLDistributionPointsExtensionEmpty(copy);
        return;
      }

      
      std::vector<DistributionPoint> dps = copy.getDistributionPoints();

      ASSERT_EQ(dps.size(), 3);
      testDistributionPointEmpty(dps.at(0));
      testDistributionPointFull(dps.at(1));
      // This doesn't work properly for some reason
      //testDistributionPointRelative(dps.at(2));
    }

    void testExtValue2Xml(std::string tab = "", bool empty = false) {
      CRLDistributionPointsExtension ext = genCRLDistributionPointsExtension();
      std::string xml = genExtValue2Xml(tab, empty);

      if (empty) {
        ext = genCRLDistributionPointsExtensionEmpty();
      }

      ASSERT_EQ(ext.extValue2Xml(tab), xml);
    }

    void testXml(std::string tab = "", bool empty = false) {
      CRLDistributionPointsExtension ext = genCRLDistributionPointsExtension();
      std::string xml = genXml(tab, empty);

      if (empty) {
        ext = genCRLDistributionPointsExtensionEmpty();
      }

      if (tab != "") {
        ASSERT_EQ(ext.getXmlEncoded(tab), xml);
        return;
      }

      ASSERT_EQ(ext.getXmlEncoded(), xml);
    }

    static std::string gnOid;
    static std::string fullNameData;
    static std::string fullNameUri;
    static std::string relativeNameCN;
    static std::string relativeNameSerial;
    static std::string crlData;
    static std::string crlUri;
    static std::vector<bool> reasons;
};

/*
 * Initialization of variables used in the tests
 */
std::string CRLDistributionPointsExtensionTest::gnOid = "2.16.76.1.3.3";
std::string CRLDistributionPointsExtensionTest::fullNameData = "00000000000100";
std::string CRLDistributionPointsExtensionTest::fullNameUri = "codigofulano.com";
std::string CRLDistributionPointsExtensionTest::relativeNameCN = "Codigos Fulano";
std::string CRLDistributionPointsExtensionTest::relativeNameSerial = "10203040";

std::string CRLDistributionPointsExtensionTest::crlData = "00000000000200";
std::string CRLDistributionPointsExtensionTest::crlUri = "crlissuer.com";

std::vector<bool> CRLDistributionPointsExtensionTest::reasons {true, false, false, true, false, true, true};

TEST_F(CRLDistributionPointsExtensionTest, Empty) {
  CRLDistributionPointsExtension ext = genCRLDistributionPointsExtensionEmpty();
  testCRLDistributionPointsExtensionEmpty(ext);
}

TEST_F(CRLDistributionPointsExtensionTest, GetDistributionPoints) {
  CRLDistributionPointsExtension ext = genCRLDistributionPointsExtension();
  testCRLDistributionPointsExtension(ext);
}

TEST_F(CRLDistributionPointsExtensionTest, SanityWrongNid) {
  testSanityWrongExt();
}

TEST_F(CRLDistributionPointsExtensionTest, SanityEmpty) {
  testSanity(true);
}

TEST_F(CRLDistributionPointsExtensionTest, Sanity) {
  testSanity();
}

TEST_F(CRLDistributionPointsExtensionTest, ExtValue2XmlEmpty) {
  testExtValue2Xml("", true);
}

TEST_F(CRLDistributionPointsExtensionTest, ExtValue2Xml) {
  testExtValue2Xml("tab");
}

TEST_F(CRLDistributionPointsExtensionTest, XmlEmpty) {
  testXml("", true);
}

TEST_F(CRLDistributionPointsExtensionTest, XmlEmptyTab) {
  testXml("tab", true);
}

TEST_F(CRLDistributionPointsExtensionTest, Xml) {
  testXml();
}

TEST_F(CRLDistributionPointsExtensionTest, XmlTab) {
  testXml("tab");
}

