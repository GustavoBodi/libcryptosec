#include <libcryptosec/certificate/PolicyQualifierInfo.h>

#include <sstream>
#include <gtest/gtest.h>
#include <stdlib.h>

/**
 * @brief Testes unitários da classe PolicyQualifierInfo
 */
class PolicyQualifierInfoTest : public ::testing::Test {

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

    std::string genXml(std::string tab = "", PolicyQualifierInfo::Type type = PolicyQualifierInfo::UNDEFINED) {
      std::string ret;
      ObjectIdentifier oid;
      UserNotice un;

      ret = tab + "<policyQualifierInfo>\n";
      
      switch (type) 
      {
        case PolicyQualifierInfo::USER_NOTICE:
          oid = ObjectIdentifierFactory::getObjectIdentifier(NID_id_qt_unotice);
          un = genUserNotice();
          ret += oid.getXmlEncoded(tab + "\t");
          ret += un.getXmlEncoded(tab + "\t");
          break;
        case PolicyQualifierInfo::CPS_URI:
          oid = ObjectIdentifierFactory::getObjectIdentifier(NID_id_qt_cps);
          ret += oid.getXmlEncoded(tab + "\t");
          ret += tab + "\t<cPSuri>" + cpsUri + "</cPSuri>\n";
          break;
        default:
          break;
      }

      ret += tab + "</policyQualifierInfo>\n";

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

      ASSERT_EQ(pqi.getType(), PolicyQualifierInfo::USER_NOTICE);
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

    void testSanityNull() {
      PolicyQualifierInfo copy = PolicyQualifierInfo(NULL);

      testEmptyPolicyQualifierInfo(copy);
    }

    void testSanityEmpty() {
      PolicyQualifierInfo pqi = genEmptyPolicyQualifierInfo();
      POLICYQUALINFO *x509 = pqi.getPolicyQualInfo();
      PolicyQualifierInfo copy = PolicyQualifierInfo(x509);

      testEmptyPolicyQualifierInfo(pqi);
      testEmptyPolicyQualifierInfo(copy);
    }

    void testSanityCpsUri() {
      PolicyQualifierInfo pqi = genPolicyQualifierInfoCpsUri();
      POLICYQUALINFO *x509 = pqi.getPolicyQualInfo();
      PolicyQualifierInfo copy = PolicyQualifierInfo(x509);

      testPolicyQualifierInfoCpsUri(pqi);
      testPolicyQualifierInfoCpsUri(copy);
    }

    void testSanityUN() {
      PolicyQualifierInfo pqi = genPolicyQualifierInfoUN();
      POLICYQUALINFO *x509 = pqi.getPolicyQualInfo();
      PolicyQualifierInfo copy = PolicyQualifierInfo(x509);

      testPolicyQualifierInfoUN(pqi);
      testPolicyQualifierInfoUN(copy);
    }

    void testXmlEmpty() {
      PolicyQualifierInfo pqi = genEmptyPolicyQualifierInfo();
      std::string xml = genXml();

      ASSERT_EQ(pqi.getXmlEncoded(), xml);
    }

    void testXmlCpsUri() {
      PolicyQualifierInfo pqi = genPolicyQualifierInfoCpsUri();
      std::string xml = genXml("", PolicyQualifierInfo::CPS_URI);

      ASSERT_EQ(pqi.getXmlEncoded(), xml);
    }

    void testXmlUN() {
      PolicyQualifierInfo pqi = genPolicyQualifierInfoUN();
      std::string xml = genXml("", PolicyQualifierInfo::USER_NOTICE);

      ASSERT_EQ(pqi.getXmlEncoded(), xml);
    }

    void testTabXmlCpsUri() {
      std::string padding = "padding";
      PolicyQualifierInfo pqi = genPolicyQualifierInfoCpsUri();
      std::string xml = genXml(padding, PolicyQualifierInfo::CPS_URI);

      ASSERT_EQ(pqi.getXmlEncoded(padding), xml);
    }

    void testTabXmlUN() {
      std::string padding = "padding";
      PolicyQualifierInfo pqi = genPolicyQualifierInfoUN();
      std::string xml = genXml(padding, PolicyQualifierInfo::USER_NOTICE);

      ASSERT_EQ(pqi.getXmlEncoded(padding), xml);
    }


    static std::string organization;
    static std::string explicitText;
    static std::string cpsUri;
    static std::string oidCpsUri;
    static std::string oidUserNotice;
    static std::string objUndefinedName;
    static std::string objCpsUriName;
    static std::string objUserNoticeName;
    static std::vector<long> noticeNumbers;
};

/*
 * Initialization of variables used in the tests
 */
std::string PolicyQualifierInfoTest::organization = "YoRHa";
std::string PolicyQualifierInfoTest::explicitText = "Glory to Mankind!";
std::string PolicyQualifierInfoTest::cpsUri = "www.example.com";
std::string PolicyQualifierInfoTest::oidCpsUri = "1.3.6.1.5.5.7.2.1";
std::string PolicyQualifierInfoTest::oidUserNotice = "1.3.6.1.5.5.7.2.2";
std::string PolicyQualifierInfoTest::objUndefinedName = "undefined";
std::string PolicyQualifierInfoTest::objCpsUriName = "id-qt-cps";
std::string PolicyQualifierInfoTest::objUserNoticeName = "id-qt-unotice";
std::vector<long> PolicyQualifierInfoTest::noticeNumbers {2};

TEST_F(PolicyQualifierInfoTest, Empty) {
  PolicyQualifierInfo pqi = genEmptyPolicyQualifierInfo();
  testEmptyPolicyQualifierInfo(pqi);
}

TEST_F(PolicyQualifierInfoTest, CpsUri) {
  PolicyQualifierInfo pqi = genPolicyQualifierInfoCpsUri();
  testPolicyQualifierInfoCpsUri(pqi);
}

TEST_F(PolicyQualifierInfoTest, UserNotice) {
  PolicyQualifierInfo pqi = genPolicyQualifierInfoUN();
  testPolicyQualifierInfoUN(pqi);
}

TEST_F(PolicyQualifierInfoTest, EmptyOID) {
  PolicyQualifierInfo pqi = genEmptyPolicyQualifierInfo();
  testOidEmptyPolicyQualifierInfo(pqi);
}

TEST_F(PolicyQualifierInfoTest, CpsUriOID) {
  PolicyQualifierInfo pqi = genPolicyQualifierInfoCpsUri();
  testOidPolicyQualifierInfoCpsUri(pqi);
}

TEST_F(PolicyQualifierInfoTest, UserNoticeOID) {
  PolicyQualifierInfo pqi = genPolicyQualifierInfoUN();
  testOidPolicyQualifierInfoUN(pqi);
}

TEST_F(PolicyQualifierInfoTest, TypeEmpty) {
  PolicyQualifierInfo pqi = genEmptyPolicyQualifierInfo();
  testTypeEmptyPolicyQualifierInfo(pqi);
}

TEST_F(PolicyQualifierInfoTest, TypeCpsUri) {
  PolicyQualifierInfo pqi = genPolicyQualifierInfoCpsUri();
  testTypePolicyQualifierInfoCpsUri(pqi);
}

TEST_F(PolicyQualifierInfoTest, TypeUserNotice) {
  PolicyQualifierInfo pqi = genPolicyQualifierInfoUN();
  testTypePolicyQualifierInfoUN(pqi);
}

TEST_F(PolicyQualifierInfoTest, SanityNull) {
  testSanityNull();
}

TEST_F(PolicyQualifierInfoTest, SanityEmpty) {
  testSanityEmpty();
}

TEST_F(PolicyQualifierInfoTest, SanityCpsUri) {
  testSanityCpsUri();
}

TEST_F(PolicyQualifierInfoTest, SanityUserNotice) {
  testSanityUN();
}

TEST_F(PolicyQualifierInfoTest, XMLEmpty) {
  testXmlEmpty();
}

TEST_F(PolicyQualifierInfoTest, XMLCpsUri) {
  testXmlCpsUri();
}

TEST_F(PolicyQualifierInfoTest, XMLUserNotice) {
  testXmlUN();
}

TEST_F(PolicyQualifierInfoTest, TabXMLCpsUri) {
  testTabXmlCpsUri();
}

TEST_F(PolicyQualifierInfoTest, TabXMLUserNotice) {
  testTabXmlUN();
}

