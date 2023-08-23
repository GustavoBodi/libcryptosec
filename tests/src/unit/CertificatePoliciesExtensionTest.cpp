#include <libcryptosec/certificate/CertificatePoliciesExtension.h>
#include <libcryptosec/certificate/BasicConstraintsExtension.h>

#include <sstream>
#include <gtest/gtest.h>
#include <stdlib.h>

/**
 * @brief Testes unitários da classe CertificatePoliciesExtension
 */
class CertificatePoliciesExtensionTest : public ::testing::Test {

protected:
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    UserNotice genUserNotice() {
      UserNotice un;

      un.setNoticeReference(organization, noticeNumbers);
      un.setExplicitText(explicitText);

      return un;
    }

    PolicyQualifierInfo genEmptyPolicyQualifierInfo() {
      return PolicyQualifierInfo();
    }

    PolicyQualifierInfo genPolicyQualifierInfoCpsUri() {
      PolicyQualifierInfo pqi;
      
      pqi.setCpsUri(cpsUri);

      return pqi;
    }

    PolicyQualifierInfo genPolicyQualifierInfoUN() {
      PolicyQualifierInfo pqi;
      UserNotice un;

      un = genUserNotice();
      pqi.setUserNotice(un);

      return pqi;
    }

    PolicyInformation genEmptyPolicyInformation() {
      return PolicyInformation();
    }

    PolicyInformation genPolicyInformation() {
      PolicyInformation pi;
      ObjectIdentifier oid;
      PolicyQualifierInfo pqi1, pqi2;

      oid = ObjectIdentifierFactory::getObjectIdentifier(oidPolicyInformation);
      pqi1 = genPolicyQualifierInfoCpsUri();
      pqi2 = genPolicyQualifierInfoUN();

      pi.setPolicyIdentifier(oid);
      pi.addPolicyQualifierInfo(pqi1);
      pi.addPolicyQualifierInfo(pqi2);

      return pi;
    }

    CertificatePoliciesExtension genEmptyCertificatePoliciesExtension() {
      return CertificatePoliciesExtension();
    }

    CertificatePoliciesExtension genCertificatePoliciesExtension() {
      CertificatePoliciesExtension cpe;
      PolicyInformation pi;

      pi = genPolicyInformation();
      cpe.addPolicyInformation(pi);

      return cpe;
    }

    std::string genEmptyExtValue2Xml() {
      return "";
    }

    std::string genExtValue2Xml(std::string tab = "") {
      std::string ret;
      PolicyInformation pi = genPolicyInformation();

      ret += pi.getXmlEncoded(tab);

      return ret;
    }

    std::string genEmptyXml(std::string tab = "") {
      std::string ret;

      ret = tab + "<certificatePolicies>\n";
		  ret += tab + "\t<extnID>" + extensionName + "</extnID>\n";
		  ret += tab + "\t<critical>no</critical>\n";
		  ret += tab + "\t<extnValue>\n";
		  ret += tab + "\t</extnValue>\n";
	    ret += tab + "</certificatePolicies>\n";
	    
      return ret;
    }

    std::string genXml(std::string tab = "") {
      std::string ret;
      PolicyInformation pi = genPolicyInformation();

      ret = tab + "<certificatePolicies>\n";
		  ret += tab + "\t<extnID>" + extensionName + "</extnID>\n";
		  ret += tab + "\t<critical>no</critical>\n";
		  ret += tab + "\t<extnValue>\n";
      ret += pi.getXmlEncoded(tab + "\t\t");
		  ret += tab + "\t</extnValue>\n";
	    ret += tab + "</certificatePolicies>\n";
	    
      return ret;
    }

    void testEmptyUserNotice(UserNotice un) {
      std::pair<std::string, std::vector<long> > noticeRef = un.getNoticeReference();
      
      ASSERT_EQ(noticeRef.first, "");
      ASSERT_EQ(noticeRef.second.size(), 0);
      ASSERT_EQ(un.getExplicitText(), "");
    }

    void testGetNoticeReference(UserNotice un) {
      std::pair<std::string, std::vector<long> > noticeRef = un.getNoticeReference();

      ASSERT_EQ(noticeRef.first, organization);
      ASSERT_EQ(noticeRef.second, noticeNumbers);
    }

    void testGetExplicitText(UserNotice un) {
      ASSERT_EQ(un.getExplicitText(), explicitText);
    }

    void testUserNotice(UserNotice un) {
      testGetNoticeReference(un);
      testGetExplicitText(un);
    }

    void testEmptyPolicyQualifierInfo(PolicyQualifierInfo pqi) {
      UserNotice un = pqi.getUserNotice();

      ASSERT_EQ(pqi.getCpsUri(), "");
      testEmptyUserNotice(un);
    }

    void testPolicyQualifierInfoCpsUri(PolicyQualifierInfo pqi) {
      UserNotice un = pqi.getUserNotice();

      ASSERT_EQ(pqi.getCpsUri(), cpsUri);
      testEmptyUserNotice(un);
    }

    void testPolicyQualifierInfoUN(PolicyQualifierInfo pqi) {
      UserNotice un = pqi.getUserNotice();

      ASSERT_EQ(pqi.getCpsUri(), "");
      testUserNotice(un);
    }

    void testOidEmptyPolicyQualifierInfo(PolicyQualifierInfo pqi) {
      ObjectIdentifier oid = pqi.getObjectIdentifier();

      ASSERT_THROW(oid.getOid(), CertificationException);
      ASSERT_EQ(oid.getName(), objUndefinedName);
    }

    void testOidPolicyQualifierInfoCpsUri(PolicyQualifierInfo pqi) {
      ObjectIdentifier oid = pqi.getObjectIdentifier();

      ASSERT_EQ(oid.getOid(), oidCpsUri);
      ASSERT_EQ(oid.getName(), objCpsUriName);
    }

    void testOidPolicyQualifierInfoUN(PolicyQualifierInfo pqi) {
      ObjectIdentifier oid = pqi.getObjectIdentifier();

      ASSERT_EQ(oid.getOid(), oidUserNotice);
      ASSERT_EQ(oid.getName(), objUserNoticeName);
    }

    void testTypeEmptyPolicyQualifierInfo(PolicyQualifierInfo pqi) {
      ASSERT_EQ(pqi.getType(), PolicyQualifierInfo::UNDEFINED);
    }

    void testTypePolicyQualifierInfoCpsUri(PolicyQualifierInfo pqi) {
      ASSERT_EQ(pqi.getType(), PolicyQualifierInfo::CPS_URI);
    }

    void testTypePolicyQualifierInfoUN(PolicyQualifierInfo pqi) {
      ASSERT_EQ(pqi.getType(), PolicyQualifierInfo::USER_NOTICE);
    }
    
    void testCpsUriGeneric(PolicyQualifierInfo pqi) {
      testPolicyQualifierInfoCpsUri(pqi);
      testOidPolicyQualifierInfoCpsUri(pqi);
      testTypePolicyQualifierInfoCpsUri(pqi);
    }

    void testUNGeneric(PolicyQualifierInfo pqi) {
      testPolicyQualifierInfoUN(pqi);
      testOidPolicyQualifierInfoUN(pqi);
      testTypePolicyQualifierInfoUN(pqi);
    }

    void testEmptyPolicyInformationIdentifier(PolicyInformation pi) {
      ObjectIdentifier oid = pi.getPolicyIdentifier();

      ASSERT_THROW(oid.getOid(), CertificationException);
      ASSERT_EQ(oid.getName(), objUndefinedName);
    }

    void testEmptyPolicyInformationPolicies(PolicyInformation pi) {
      std::vector<PolicyQualifierInfo> policies = pi.getPoliciesQualifierInfo();

      ASSERT_EQ(policies.size(), 0);
    }

    void testPolicyInformationIdentifier(PolicyInformation pi) {
      ObjectIdentifier oid = pi.getPolicyIdentifier();

      ASSERT_EQ(oid.getOid(), oidPolicyInformation);
      ASSERT_EQ(oid.getName(), objPolicyInformationName);
    }

    void testPolicyInformationPolicies(PolicyInformation pi) {
      std::vector<PolicyQualifierInfo> policies = pi.getPoliciesQualifierInfo();

      ASSERT_EQ(policies.size(), 2);
      testCpsUriGeneric(policies.at(0));
      testUNGeneric(policies.at(1));
    }

    void testGenericEmptyPolicyInformation(PolicyInformation pi) {
      testEmptyPolicyInformationIdentifier(pi);
      testEmptyPolicyInformationPolicies(pi);
    }

    void testGenericPolicyInformation(PolicyInformation pi) {
      testPolicyInformationIdentifier(pi);
      testPolicyInformationPolicies(pi);
    }

    void testEmptyCertificatePoliciesExtension(CertificatePoliciesExtension cpe) {
      std::vector<PolicyInformation> pis = cpe.getPoliciesInformation();

      ASSERT_EQ(pis.size(), 0);
    }

    void testCertificatePoliciesExtension(CertificatePoliciesExtension cpe) {
      std::vector<PolicyInformation> pis = cpe.getPoliciesInformation();

      ASSERT_EQ(pis.size(), 1);
      testGenericPolicyInformation(pis.at(0));
    }

    void testSanityNull() {
      ASSERT_THROW(CertificatePoliciesExtension(NULL), CertificationException);
    }

    void testSanityEmpty() {
      CertificatePoliciesExtension cpe = genEmptyCertificatePoliciesExtension();
      X509_EXTENSION *x509 = cpe.getX509Extension();
      CertificatePoliciesExtension copy = CertificatePoliciesExtension(x509);

      testEmptyCertificatePoliciesExtension(copy);
    }

    void testSanity() {
      CertificatePoliciesExtension cpe = genCertificatePoliciesExtension();
      X509_EXTENSION *x509 = cpe.getX509Extension();
      CertificatePoliciesExtension copy = CertificatePoliciesExtension(x509);

      testCertificatePoliciesExtension(copy);
    }

    void testExtValue2XmlEmpty() {
      CertificatePoliciesExtension cpe = genEmptyCertificatePoliciesExtension();
      std::string xml = genEmptyExtValue2Xml();

      ASSERT_EQ(cpe.extValue2Xml(), xml);
    }

    void testExtValue2Xml(std::string tab = "") {
      CertificatePoliciesExtension cpe = genCertificatePoliciesExtension();
      std::string xml = genExtValue2Xml(tab);

      ASSERT_EQ(cpe.extValue2Xml(tab), xml);
    }

    void testXmlEmpty(std::string tab = "") {
      CertificatePoliciesExtension cpe = genEmptyCertificatePoliciesExtension();
      std::string xml = genEmptyXml(tab);

      ASSERT_EQ(cpe.getXmlEncoded(tab), xml);
    }

    void testXml(std::string tab = "") {
      CertificatePoliciesExtension cpe = genCertificatePoliciesExtension();
      std::string xml = genXml(tab);

      ASSERT_EQ(cpe.getXmlEncoded(tab), xml);
    }

    static std::string organization;
    static std::string explicitText;
    static std::string cpsUri;
    static std::string oidCpsUri;
    static std::string oidUserNotice;
    static std::string oidPolicyInformation;
    static std::string objUndefinedName;
    static std::string objCpsUriName;
    static std::string objUserNoticeName;
    static std::string objPolicyInformationName;
    static std::string extensionName;
    static std::vector<long> noticeNumbers;
};

/*
 * Initialization of variables used in the tests
 */
std::string CertificatePoliciesExtensionTest::organization = "YoRHa";
std::string CertificatePoliciesExtensionTest::explicitText = "Glory to Mankind!";
std::string CertificatePoliciesExtensionTest::cpsUri = "www.example.com";
std::string CertificatePoliciesExtensionTest::oidCpsUri = "1.3.6.1.5.5.7.2.1";
std::string CertificatePoliciesExtensionTest::oidUserNotice = "1.3.6.1.5.5.7.2.2";
std::string CertificatePoliciesExtensionTest::oidPolicyInformation = "1.3.6.1.5.5.7.13.1";
std::string CertificatePoliciesExtensionTest::objUndefinedName = "undefined";
std::string CertificatePoliciesExtensionTest::objCpsUriName = "id-qt-cps";
std::string CertificatePoliciesExtensionTest::objUserNoticeName = "id-qt-unotice";
std::string CertificatePoliciesExtensionTest::objPolicyInformationName = "1.3.6.1.5.5.7.13.1";
std::string CertificatePoliciesExtensionTest::extensionName = "certificatePolicies";
std::vector<long> CertificatePoliciesExtensionTest::noticeNumbers {2};

TEST_F(CertificatePoliciesExtensionTest, Empty) {
  CertificatePoliciesExtension cpe = genEmptyCertificatePoliciesExtension();
  testEmptyCertificatePoliciesExtension(cpe);
}

TEST_F(CertificatePoliciesExtensionTest, PolicyInformation) {
  CertificatePoliciesExtension cpe = genCertificatePoliciesExtension();
  testCertificatePoliciesExtension(cpe);
}

TEST_F(CertificatePoliciesExtensionTest, SanityNull) {
  testSanityNull();
}

TEST_F(CertificatePoliciesExtensionTest, SanityEmpty) {
  testSanityEmpty();
}

TEST_F(CertificatePoliciesExtensionTest, Sanity) {
  testSanity();
}

TEST_F(CertificatePoliciesExtensionTest, ExtValue2XmlEmpty) {
  testExtValue2XmlEmpty();
}

TEST_F(CertificatePoliciesExtensionTest, ExtValue2Xml) {
  testExtValue2Xml();
}

TEST_F(CertificatePoliciesExtensionTest, ExtValue2XmlTab) {
  testExtValue2Xml("tab");
}

TEST_F(CertificatePoliciesExtensionTest, XmlEmpty) {
  testXmlEmpty();
}

TEST_F(CertificatePoliciesExtensionTest, Xml) {
  testXml();
}

TEST_F(CertificatePoliciesExtensionTest, XmlTab) {
  testXml("tab");
}
