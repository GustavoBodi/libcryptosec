#include <libcryptosec/certificate/ObjectIdentifierFactory.h>

#include <sstream>
#include <gtest/gtest.h>
#include <stdlib.h>

/**
 * @brief Testes unitários da classe GeneralName
 */
class ObjectIdentifierFactoryTest : public ::testing::Test {

protected:
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    ObjectIdentifier genFromString() {
      return ObjectIdentifierFactory::getObjectIdentifier(oid);
    }
   
    ObjectIdentifier genFromNid() {
      return ObjectIdentifierFactory::getObjectIdentifier(nid);
    }

    ObjectIdentifier genObjectIdentifier() {
      ObjectIdentifier obj = ObjectIdentifierFactory::createObjectIdentifier(createOid, createName);
      createNid = obj.getNid();
      return obj;
    }

    ObjectIdentifier genFromNidCreate() {
      return ObjectIdentifierFactory::getObjectIdentifier(createNid);
    }

    void testObjectIdentifier(ObjectIdentifier obj) {
      ASSERT_EQ(obj.getOid(), oid);
      ASSERT_EQ(obj.getNid(), nid);
      ASSERT_EQ(obj.getName(), name);
      ASSERT_EQ(obj.getXmlEncoded(), xml);
    }

    void testObjectIdentifierCreate(ObjectIdentifier obj) {
      ASSERT_EQ(obj.getOid(), createOid);
      ASSERT_EQ(obj.getNid(), createNid);
      ASSERT_EQ(obj.getName(), createName);
      ASSERT_EQ(obj.getXmlEncoded(), createXml);
    }

    void testSanity() {
      std::vector<ObjectIdentifier> objs;

      objs.push_back(genFromString());
      objs.push_back(genFromNid());
      objs.push_back(genFromNidCreate());

      for (unsigned int i = 0; i < objs.size(); i++) {
        ASN1_OBJECT *x509 = objs.at(i).getObjectIdentifier();
        ObjectIdentifier copy(x509);

        if (i < objs.size() - 1) {
          testObjectIdentifier(copy);
          continue;
        }

        testObjectIdentifierCreate(copy);
      }
    }

    void testThrowFromString() {
      ASSERT_THROW(
          ObjectIdentifierFactory::getObjectIdentifier("kaboom"),
          CertificationException);
    }

    void testThrowFromNid() {
      ASSERT_THROW(
          ObjectIdentifierFactory::getObjectIdentifier(std::numeric_limits<int>::max()),
          CertificationException);
    }

    void testThrowFromCreate() {
      ASSERT_THROW(
          ObjectIdentifierFactory::createObjectIdentifier(oid, name),
          CertificationException);
    }

    static int nid;
    static std::string oid;
    static std::string name;
    static std::string xml;
    int createNid;
    static std::string createOid;
    static std::string createName;
    static std::string createXml;
};

/*
 * Initialization of variables used in the tests
 */
int ObjectIdentifierFactoryTest::nid = 14;
std::string ObjectIdentifierFactoryTest::oid = "2.5.4.6";
std::string ObjectIdentifierFactoryTest::name = "C";
std::string ObjectIdentifierFactoryTest::xml = "<oid>2.5.4.6</oid>\n";

std::string ObjectIdentifierFactoryTest::createOid = "2.16.76.1.3.3";
std::string ObjectIdentifierFactoryTest::createName = "CNPJ";
std::string ObjectIdentifierFactoryTest::createXml = "<oid>2.16.76.1.3.3</oid>\n";

TEST_F(ObjectIdentifierFactoryTest, FromString) {
  ObjectIdentifier obj = genFromString();
  testObjectIdentifier(obj);
}

TEST_F(ObjectIdentifierFactoryTest, FromNid) {
  ObjectIdentifier obj = genFromNid();
  testObjectIdentifier(obj);
}

TEST_F(ObjectIdentifierFactoryTest, CreateObjectIdentifier) {
  ObjectIdentifier obj = genObjectIdentifier();
  testObjectIdentifierCreate(obj);
}

TEST_F(ObjectIdentifierFactoryTest, TestSanity) {
  testSanity();
}

TEST_F(ObjectIdentifierFactoryTest, ThrowFromString) {
  testThrowFromString();
}

TEST_F(ObjectIdentifierFactoryTest, ThrowFromNid) {
  testThrowFromNid();
}

TEST_F(ObjectIdentifierFactoryTest, ThrowFromCreate) {
  testThrowFromCreate();
}

