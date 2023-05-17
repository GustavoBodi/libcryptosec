#include <libcryptosec/certificate/RDNSequence.h>

#include <sstream>
#include <gtest/gtest.h>


/**
 * @brief Testes unitários da classe RDNSequence.
 */
class RDNSequenceTest : public ::testing::Test {


protected:
    virtual void SetUp() {
    }

    virtual void TearDown() {
    }

    RDNSequence genRDNSequence() {
      RDNSequence rdn;

      for (unsigned int i = 0; i < data.size(); i++) {
        RDNSequence::EntryType type = (RDNSequence::EntryType) i;

        rdn.addEntry(type, data.at(i));
      }

      return rdn;
    }

    RDNSequence genRDNSequenceVector() {
      RDNSequence rdn;
      rdn.addEntry(RDNSequence::COMMON_NAME, dataVector);
      return rdn;
    }

    std::string genXml() {
      std::string ret;

      ret = "<RDNSequence>\n";

      for (unsigned int i = 0; i < entryNamesXml.size(); i++) {
        std::string entryNameXml = entryNamesXml.at(i);
        std::string entryData = data.at(i);

        ret += "\t<" + entryNameXml + ">" + entryData + "</" + entryNameXml + ">\n";
      }

      ret += "</RDNSequence>\n";

      return ret;
    }

    void testGetEntriesType(RDNSequence rdn) {
      for (unsigned int i = 0; i < data.size(); i++) {
        std::vector<std::string> entries = rdn.getEntries((RDNSequence::EntryType) i);

        ASSERT_EQ(entries.size(), 1);
        ASSERT_EQ(entries.at(0), data.at(i));
      }
    }

    void testGetEntries(RDNSequence rdn) {
      std::vector<std::pair<ObjectIdentifier, std::string> > entries = rdn.getEntries();

      for (unsigned int i = 0; i < entries.size(); i++) {
        std::pair<ObjectIdentifier, std::string> dataPair = entries.at(i);

        ASSERT_EQ(dataPair.first.getName(), entryNames.at(i));
        ASSERT_EQ(dataPair.second, data.at(i));
      }
    }

    void testGetEntriesTypeVector(RDNSequence rdn) {
      std::vector<std::string> entries = rdn.getEntries(RDNSequence::COMMON_NAME);

      ASSERT_EQ(entries.at(0), dataVector.at(0));
      ASSERT_EQ(entries.at(1), dataVector.at(1));
    }

    void testXml(RDNSequence rdn) {
      std::string xml = genXml();

      ASSERT_EQ(rdn.getXmlEncoded(), xml);
    }
  
    void testGeneric(RDNSequence rdn) {
      testGetEntriesType(rdn);
      testGetEntries(rdn);
      testXml(rdn);
    }

    void testSanity() {
      RDNSequence rdn = genRDNSequence();
      X509_NAME *x509 = rdn.getX509Name();
      RDNSequence copy(x509);

      testGeneric(copy);
    }

    static std::vector<std::string> data;
    static std::vector<std::string> dataVector;
    static std::vector<std::string> entryNames;
    static std::vector<std::string> entryNamesXml;
};

/*
 * Initialization of variables used in the tests
 */
std::vector<std::string> RDNSequenceTest::data {"BR", "SC", "Florianopolis", "UFSC", "LabSEC", "Fulano da Silva", 
                                                "fulano.da.silva@mail.com", "Codigos Fulano da Silva", "177013", "Dr. Prof. Eng.",
                                                "da Silva", "Fulano", "FS", "Codigos Fulano", "Jr.", "fulanos-codigo"};

// As much as having two common names seems weird, its just for testing sake
std::vector<std::string> RDNSequenceTest::dataVector {"Fulano da Silva", "Fulana de Souza"};

std::vector<std::string> RDNSequenceTest::entryNames {"C", "ST", "L", "O", "OU", "CN", "emailAddress", "dnQualifier",
                                                      "serialNumber", "title", "SN", "GN", "initials", "pseudonym",
                                                      "generationQualifier", "DC"};

std::vector<std::string> RDNSequenceTest::entryNamesXml {"countryName", "stateOrProvinceName", "localityName", "organizationName",
                                                         "organizationalUnitName", "commonName", "e-mail", "dnQualifier",
                                                         "serialNumber", "title", "surname", "givenName", "initials",
                                                         "pseudonym", "generationQualifier", "domainComponent"};

TEST_F(RDNSequenceTest, GetEntriesType) {
  RDNSequence rdn = genRDNSequence();
  testGetEntriesType(rdn);
}

TEST_F(RDNSequenceTest, GetEntries) {
  RDNSequence rdn = genRDNSequence();
  testGetEntries(rdn);
}

TEST_F(RDNSequenceTest, XMLEncoded) {
  RDNSequence rdn = genRDNSequence();
  testXml(rdn);
}

TEST_F(RDNSequenceTest, Sanity) {
  testSanity();
}
