#include <libcryptosec/certificate/ObjectIdentifierFactory.h>

#include <sstream>
#include <gtest/gtest.h>


/**
 * @brief Testes unitários das classes ObjectIdentifier
 */
class ObjectIdentifierTest : public ::testing::Test {

protected:
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    ObjectIdentifier genEmpty() {
      return ObjectIdentifier();
    }

    ObjectIdentifier genObjectIdentifier() {
      return ObjectIdentifierFactory::getObjectIdentifier(oid);
    }

    void testGetOid(ObjectIdentifier obj) {
      ASSERT_EQ(obj.getOid(), oid);
    }

    void testGetNid(ObjectIdentifier obj) {
      ASSERT_EQ(obj.getNid(), nid); 
    }

    void testGetName(ObjectIdentifier obj) {
      ASSERT_EQ(obj.getName(), name);
    }

    void testXmlEncoded(ObjectIdentifier obj) {
      ASSERT_EQ(obj.getXmlEncoded(), xml);
    }

    void testGetOidEmpty(ObjectIdentifier obj) {
      ASSERT_THROW(obj.getOid(), CertificationException);
    }

    void testGetNidEmpty(ObjectIdentifier obj) {
      ASSERT_EQ(obj.getNid(), NID_undef);
    }

    void testGetNameEmpty(ObjectIdentifier obj) {
      ASSERT_EQ(obj.getName(), nameEmpty);
    }

    void testXmlEncodedEmpty(ObjectIdentifier obj) {
      ASSERT_EQ(obj.getXmlEncoded(), xmlEmpty);
    }

    void testGeneric(ObjectIdentifier obj) {
      testGetOid(obj);
      testGetNid(obj);
      testGetName(obj);
      testXmlEncoded(obj);
    }

    void testSanity() {
      ObjectIdentifier obj = genObjectIdentifier();
      ASN1_OBJECT *asn1 = obj.getObjectIdentifier();
      ObjectIdentifier copy(asn1);

      testGeneric(obj);
      testGeneric(copy);
    }

    void testAssignment() {
      ObjectIdentifier obj = genObjectIdentifier();
      ObjectIdentifier copy = obj;

      testGeneric(obj);
      testGeneric(copy);
    }

    static int nid;
    static std::string oid;
    static std::string name;
    static std::string xml;
    static std::string nameEmpty;
    static std::string xmlEmpty;
};

/*
 * Initialization of variables used in the tests
 */
int ObjectIdentifierTest::nid = 14;
std::string ObjectIdentifierTest::oid = "2.5.4.6";
std::string ObjectIdentifierTest::name = "C";
std::string ObjectIdentifierTest::xml = "<oid>2.5.4.6</oid>\n";

std::string ObjectIdentifierTest::nameEmpty = "undefined";
std::string ObjectIdentifierTest::xmlEmpty = "<oid></oid>\n";

TEST_F(ObjectIdentifierTest, GetOid) {
  ObjectIdentifier obj = genObjectIdentifier();
  testGetOid(obj);
}

TEST_F(ObjectIdentifierTest, GetNid) {
  ObjectIdentifier obj = genObjectIdentifier();
  testGetNid(obj);
}

TEST_F(ObjectIdentifierTest, GetName) {
  ObjectIdentifier obj = genObjectIdentifier();
  testGetName(obj);
}

TEST_F(ObjectIdentifierTest, XMLEncoded) {
  ObjectIdentifier obj = genObjectIdentifier();
  testXmlEncoded(obj);
}

TEST_F(ObjectIdentifierTest, GetOidEmpty) {
  ObjectIdentifier obj = genEmpty();
  testGetOidEmpty(obj);
}

TEST_F(ObjectIdentifierTest, GetNidEmpty) {
  ObjectIdentifier obj = genEmpty();
  testGetNidEmpty(obj);
}

TEST_F(ObjectIdentifierTest, GetNameEmpty) {
  ObjectIdentifier obj = genEmpty();
  testGetNameEmpty(obj);
}

TEST_F(ObjectIdentifierTest, XMLEncodedEmpty) {
  ObjectIdentifier obj = genEmpty();
  testXmlEncodedEmpty(obj);
}

TEST_F(ObjectIdentifierTest, Sanity) {
  testSanity();
}

TEST_F(ObjectIdentifierTest, Assignment) {
  testAssignment();
}

