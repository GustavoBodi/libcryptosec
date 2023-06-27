#include <libcryptosec/certificate/UserNotice.h>

#include <sstream>
#include <gtest/gtest.h>
#include <stdlib.h>

/**
 * @brief Testes unitários da classe UserNotice
 */
class UserNoticeTest : public ::testing::Test {

protected:
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    UserNotice genEmpty() {
      UserNotice un;
      return un;
    }

    UserNotice genUserNotice() {
      UserNotice un;

      un.setNoticeReference(organization, noticeNumbers);
      un.setExplicitText(explicitText);

      return un;
    }

    std::string genXml(std::string tab = "", bool empty = false) {
      std::string xml = tab + "<userNotice>\n";

      if (!empty) {
        xml += tab + "\t<noticeRef>\n";
        xml += tab + "\t\t<organization>" + organization + "</organization>\n";
        xml += tab + "\t\t<noticeNumbers>" + to_string(noticeNumbers.at(0)) + "</noticeNumbers>\n";
        xml += tab + "\t</noticeRef>\n";
        xml += tab + "\t<explicitText>" + explicitText + "</explicitText>\n";
      }

      xml += tab + "</userNotice>\n";

      return xml;
    }

    void testEmpty(UserNotice un) {
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

    void testGeneric(UserNotice un) {
      testGetNoticeReference(un);
      testGetExplicitText(un);
    }

    void testSanityEmpty() {
      UserNotice un = genEmpty();
      USERNOTICE* x509 = un.getUserNotice();
      UserNotice copy(x509);

      testEmpty(un);
    }

    void testSanity() {
      UserNotice un = genUserNotice();
      USERNOTICE* x509 = un.getUserNotice();
      UserNotice copy(x509);

      testGeneric(un);
    }

    void testSanityNull() {
      USERNOTICE *x509 = NULL;
      UserNotice copy(x509);

      testEmpty(copy);
    }

    void testEmptyXml() {
      UserNotice un = genEmpty();
      std::string xml = genXml("", true);

      ASSERT_EQ(un.getXmlEncoded(), xml);
    }

    void testXml() {
      UserNotice un = genUserNotice();
      std::string xml = genXml();

      ASSERT_EQ(un.getXmlEncoded(), xml);
    }

    void testTabXml() {
      UserNotice un = genUserNotice();
      std::string xml = genXml("tab");
     
      ASSERT_EQ(un.getXmlEncoded("tab"), xml);
    }

    static std::string organization;
    static std::string explicitText;
    static std::vector<long> noticeNumbers;
};

/*
 * Initialization of variables used in the tests
 */
std::string UserNoticeTest::organization = "YoRHa";
std::string UserNoticeTest::explicitText = "Glory to Mankind!";
std::vector<long> UserNoticeTest::noticeNumbers {2};

TEST_F(UserNoticeTest, Empty) {
  UserNotice un = genEmpty();
  testEmpty(un);
}

TEST_F(UserNoticeTest, GetNoticeReference) {
  UserNotice un = genUserNotice();
  testGetNoticeReference(un);
}

TEST_F(UserNoticeTest, GetExplicitText) {
  UserNotice un = genUserNotice();
  testGetExplicitText(un);
}

TEST_F(UserNoticeTest, EmptySanityTest) {
  testSanityEmpty();
}

TEST_F(UserNoticeTest, SanityTest) {
  testSanity();
}

TEST_F(UserNoticeTest, NullSanityTest) {
  testSanityNull();
}

TEST_F(UserNoticeTest, EmptyXML) {
  testEmptyXml();
}

TEST_F(UserNoticeTest, XML) {
  testXml();
}

TEST_F(UserNoticeTest, TabXML) {
  testTabXml();
}
