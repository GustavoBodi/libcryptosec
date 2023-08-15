#include <libcryptosec/certificate/PolicyInformation.h>

#include <sstream>
#include <gtest/gtest.h>
#include <stdlib.h>

/**
 * @brief Testes unitários da classe PolicyInformation
 */
class PolicyInformationTest : public ::testing::Test {

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

    std::string genXml(PolicyInformation pi, std::string tab = "") {
      std::string ret;
      std::vector<PolicyQualifierInfo> pqis = pi.getPoliciesQualifierInfo();
      ObjectIdentifier oid = pi.getPolicyIdentifier();

      ret = tab + "<policyInformation>\n";
      ret += oid.getXmlEncoded(tab + "\t");
      for (unsigned int i = 0; i < pqis.size(); i++) {
        ret += pqis.at(i).getXmlEncoded(tab + "\t");
      }
      ret += tab + "</policyInformation>\n";

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

    void testSanityEmpty() {
      PolicyInformation pi = genEmptyPolicyInformation();
      POLICYINFO *x509 = pi.getPolicyInfo();
      PolicyInformation copy = PolicyInformation(x509);

      testGenericEmptyPolicyInformation(copy);
    }

    void testSanity() {
      PolicyInformation pi = genPolicyInformation();
      POLICYINFO *x509 = pi.getPolicyInfo();
      PolicyInformation copy = PolicyInformation(x509);

      testGenericPolicyInformation(copy);
    }

    void testXmlEmpty() {
      PolicyInformation pi = genEmptyPolicyInformation();
      std::string xml = genXml(pi);

      ASSERT_EQ(pi.getXmlEncoded(), xml);
    }

    void testXml() {
      PolicyInformation pi = genPolicyInformation();
      std::string xml = genXml(pi);

      ASSERT_EQ(pi.getXmlEncoded(), xml);
    }

    void testXmlTab() {
      std::string tab = "tab";
      PolicyInformation pi = genPolicyInformation();
      std::string xml = genXml(pi, tab);

      ASSERT_EQ(pi.getXmlEncoded(tab), xml);
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
    static std::vector<long> noticeNumbers;
};

/*
 * Initialization of variables used in the tests
 */
std::string PolicyInformationTest::organization = "YoRHa";
std::string PolicyInformationTest::explicitText = "Glory to Mankind!";
std::string PolicyInformationTest::cpsUri = "www.example.com";
std::string PolicyInformationTest::oidCpsUri = "1.3.6.1.5.5.7.2.1";
std::string PolicyInformationTest::oidUserNotice = "1.3.6.1.5.5.7.2.2";
std::string PolicyInformationTest::oidPolicyInformation = "1.3.6.1.5.5.7.13.1";
std::string PolicyInformationTest::objUndefinedName = "undefined";
std::string PolicyInformationTest::objCpsUriName = "id-qt-cps";
std::string PolicyInformationTest::objUserNoticeName = "id-qt-unotice";
std::string PolicyInformationTest::objPolicyInformationName = "1.3.6.1.5.5.7.13.1";
std::vector<long> PolicyInformationTest::noticeNumbers {2};

TEST_F(PolicyInformationTest, PolicyIdentifierEmpty) {
  PolicyInformation pi = genEmptyPolicyInformation();
  testEmptyPolicyInformationIdentifier(pi);
}

TEST_F(PolicyInformationTest, PolicyIdentifier) {
  PolicyInformation pi = genPolicyInformation();
  testPolicyInformationIdentifier(pi);
}

TEST_F(PolicyInformationTest, PoliciesQualifierEmpty) {
  PolicyInformation pi = genEmptyPolicyInformation();
  testEmptyPolicyInformationPolicies(pi);
}

TEST_F(PolicyInformationTest, PoliciesQualifier) {
  PolicyInformation pi = genPolicyInformation();
  testPolicyInformationPolicies(pi);
}

TEST_F(PolicyInformationTest, SanityEmpty) {
  testSanityEmpty();
}

TEST_F(PolicyInformationTest, Sanity) {
  testSanity();
}

TEST_F(PolicyInformationTest, XmlEmpty) {
  testXmlEmpty();
}

TEST_F(PolicyInformationTest, Xml) {
  testXml();
}

TEST_F(PolicyInformationTest, XmlTab) {
  testXmlTab();
}

