#include <libcryptosec/certificate/DeltaCRLIndicatorExtension.h>

#include <gtest/gtest.h>
#include <stdlib.h>

/**
 * @brief Testes unitários da classe DeltaCRLIndicatorExtension
 */
class DeltaCRLIndicatorExtensionTest : public ::testing::Test {

protected:
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    DeltaCRLIndicatorExtension genExtension() {
      DeltaCRLIndicatorExtension ext(baseCrlNumber);
      
      return ext;
    }

    DeltaCRLIndicatorExtension genExtensionSetSerial() {
      DeltaCRLIndicatorExtension ext(baseCrlNumber);
      
      ext.setSerial(diffCrlSerial);

      return ext;
    }

    std::string genExtValue2Xml(std::string tab, int crlNumber) {
      std::string ret = tab + "\t<baseCRLNumber>" + std::to_string(crlNumber) + "</baseCRLNumber>\n";

      return ret;
    }

    std::string genXml(std::string tab, int crlNumber) {
      std::string ret = "";

      ret += tab + "<deltaCRLIndicator>\n";
	    ret += tab + "\t<extnID>deltaCRL</extnID>\n";
	    ret += tab + "\t<critical>no</critical>\n";
    	ret += tab + "\t<extnValue>\n";
	    ret += tab + "\t\t<baseCRLNumber>" + std::to_string(crlNumber) + "</baseCRLNumber>\n";
    	ret += tab + "\t</extnValue>\n";
    	ret += tab + "</deltaCRLIndicator>\n";

      return ret;
    }

    void testExtension(DeltaCRLIndicatorExtension ext) {
      ASSERT_EQ(ext.getSerial(), baseCrlNumber);
    }

    void testExtensionSetSerial(DeltaCRLIndicatorExtension ext) {
      ASSERT_NE(ext.getSerial(), baseCrlNumber);
      ASSERT_EQ(ext.getSerial(), diffCrlSerial);
    }

    void testSanity() {
      DeltaCRLIndicatorExtension ext = genExtension();
      X509_EXTENSION *x509 = ext.getX509Extension();
      DeltaCRLIndicatorExtension copy(x509);

      testExtension(ext);
      testExtension(copy);
    }

    void testExtValue2Xml() {
      DeltaCRLIndicatorExtension ext = genExtension();
      std::string value = genExtValue2Xml("", baseCrlNumber);

      ASSERT_EQ(ext.extValue2Xml(), value);
    }
    
    void testExtValue2XmlTab(std::string tab) {
      DeltaCRLIndicatorExtension ext = genExtension();
      std::string value = genExtValue2Xml(tab, baseCrlNumber);

      ASSERT_EQ(ext.extValue2Xml(tab), value);
    }

    void testXml() {
      DeltaCRLIndicatorExtension ext = genExtension();
      std::string value = genXml("", baseCrlNumber);

      ASSERT_EQ(ext.getXmlEncoded(), value);
    }

    void testXmlTab(std::string tab) {
      DeltaCRLIndicatorExtension ext = genExtension();
      std::string value = genXml(tab, baseCrlNumber);

      ASSERT_EQ(ext.getXmlEncoded(tab), value);
    }

    static int baseCrlNumber;
    static int diffCrlSerial;
};

/*
 * Initialization of variables used in the tests
 */
int DeltaCRLIndicatorExtensionTest::baseCrlNumber = 23022017;
int DeltaCRLIndicatorExtensionTest::diffCrlSerial = 23042021;

TEST_F(DeltaCRLIndicatorExtensionTest, Constructor) {
  DeltaCRLIndicatorExtension ext = genExtension();
  testExtension(ext);
}

TEST_F(DeltaCRLIndicatorExtensionTest, SetSerial) {
  DeltaCRLIndicatorExtension ext = genExtensionSetSerial();
  testExtensionSetSerial(ext);
}

TEST_F(DeltaCRLIndicatorExtensionTest, Sanity) {
  testSanity();
}

TEST_F(DeltaCRLIndicatorExtensionTest, ExtValue2Xml) {
  testExtValue2Xml();
}

TEST_F(DeltaCRLIndicatorExtensionTest, ExtValue2XmlTab) {
  testExtValue2XmlTab("tab");
}

TEST_F(DeltaCRLIndicatorExtensionTest, Xml) {
  testXml();
}

TEST_F(DeltaCRLIndicatorExtensionTest, XmlTab) {
  testXmlTab("tab");
}

