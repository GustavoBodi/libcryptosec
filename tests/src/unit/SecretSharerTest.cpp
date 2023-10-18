#include <libcryptosec/SecretSharer.h>

#include <sstream>
#include <gtest/gtest.h>

/*
 * @brief Tests unitários da classe SecretSharer
 */
class SecretSharerTest : public ::testing::Test {

protected:
    virtual void SetUp() {
        fullSecret = Random::bytes(keySize/64);
    }

    virtual void TearDown() {
    }

    ByteArray joinSecret(unsigned int secretSize, unsigned int nParts, unsigned int threshold, std::vector<std::ostream *> *secretPartsSplit) {  
        std::vector<std::istream *> secretPartsJoin;
        for(unsigned int j = 0; j < secretSize; j++) {
            ByteArray piece = ByteArray((std::ostringstream *)(secretPartsSplit->at(j)));
            secretPartsJoin.push_back((std::istream *) piece.toStream());
        }
        std::ostream *recoveredSecret = new std::ostringstream();
        SecretSharer::join(&secretPartsJoin, nParts, threshold, recoveredSecret);
        ByteArray secret = ByteArray((std::ostringstream *) recoveredSecret);
        return secret;
    }

    std::vector<std::ostream *> splitSecret(unsigned int secretSize, unsigned int nParts, unsigned int treshold) {    
        std::vector<std::ostream *> secretParts;
        for(unsigned int i = 0; i < secretSize; i++) {
            secretParts.push_back(new std::ostringstream());
        }
        SecretSharer::split(fullSecret.toStream(), nParts, treshold, &secretParts);
        return secretParts;
    }

    void testJoinSecret(unsigned int secretSize, unsigned int nParts, unsigned int threshold, std::vector<std::ostream *> *secretPartsSplit) {  
        ByteArray joinedSecret = joinSecret(secretSize, nParts, threshold, secretPartsSplit);
        ASSERT_EQ(joinedSecret, fullSecret);
    }

    void testJoinInvalidParam(unsigned int secretSize, unsigned int nParts, unsigned int threshold, std::vector<std::ostream *> *secretPartsSplit) {    
        ASSERT_THROW(joinSecret(secretSize, nParts, threshold, secretPartsSplit), SecretSharerException);
    }

    void testSplitInvalidParam(unsigned int secretSize, unsigned int nParts, unsigned int threshold) {
        ASSERT_THROW(splitSecret(secretSize, nParts, threshold), SecretSharerException);
    }

    static unsigned int keySize;
    ByteArray fullSecret;
};

/*
 * Initialization of variables used in the tests
 */
unsigned int SecretSharerTest::keySize = 1024;

TEST_F(SecretSharerTest, joinValid) {
    unsigned int splitSecretSize = 4;
    unsigned int splitParts = 4;
    unsigned int splitThreshold = 3;
    std::vector<std::ostream *> secretParts = splitSecret(splitSecretSize, splitParts, splitThreshold);

    unsigned int joinSecretSize = 4;
    unsigned int joinParts = 4;
    unsigned int joinThreshold = 3;
    testJoinSecret(joinSecretSize, joinParts, joinThreshold, &secretParts);
}

TEST_F(SecretSharerTest, joinValidTresholdEquals1) {
    unsigned int splitSecretSize = 2;
    unsigned int splitParts = 2;
    unsigned int splitThreshold = 1;
    std::vector<std::ostream *> secretParts = splitSecret(splitSecretSize, splitParts, splitThreshold);

    unsigned int joinSecretSize = 2;
    unsigned int joinParts = 2;
    unsigned int joinThreshold = 1;
    testJoinSecret(joinSecretSize, joinParts, joinThreshold, &secretParts);
}

TEST_F(SecretSharerTest, joinValidThresholdEqualsParts) {
    unsigned int splitSecretSize = 2;
    unsigned int splitParts = 2;
    unsigned int splitThreshold = 2;
    std::vector<std::ostream *> secretParts = splitSecret(splitSecretSize, splitParts, splitThreshold);

    unsigned int joinSecretSize = 2;
    unsigned int joinParts = 2;
    unsigned int joinThreshold = 2;
    testJoinSecret(joinSecretSize, joinParts, joinThreshold, &secretParts);
}

TEST_F(SecretSharerTest, joinInvalidNumParts) {
    unsigned int splitSecretSize = 2;    
    unsigned int splitParts = 2;
    unsigned int splitThreshold = 2;
    std::vector<std::ostream *> secretParts = splitSecret(splitSecretSize, splitParts, splitThreshold);

    unsigned int joinSecretSize = 2;
    unsigned int joinParts = 0;
    unsigned int joinThreshold = 2;
    testJoinInvalidParam(joinSecretSize, joinParts, joinThreshold, &secretParts);
}

TEST_F(SecretSharerTest, joinInvalidThreshold) {
    unsigned int splitSecretSize = 2;   
    unsigned int splitParts = 2;
    unsigned int splitThreshold = 2;
    std::vector<std::ostream *> secretParts = splitSecret(splitSecretSize, splitParts, splitThreshold);

    unsigned int joinSecretSize = 2;
    unsigned int joinParts = 2;
    unsigned int joinThreshold = 0;
    testJoinInvalidParam(joinSecretSize, joinParts, joinThreshold, &secretParts);
}

/**
 * @brief Test if the number of parts the secret was split into is less than the threshold when calling SecretSharer::join()
 */
TEST_F(SecretSharerTest, joinLessNumParts) {
    unsigned int splitSecretSize = 4;
    unsigned int splitParts = 2;
    unsigned int splitThreshold = 2;
    std::vector<std::ostream *> secretParts = splitSecret(splitSecretSize, splitParts, splitThreshold);

    unsigned int joinSecretSize = 4;
    unsigned int joinParts = 2;
    unsigned int joinThreshold = 4;
    testJoinInvalidParam(joinSecretSize, joinParts, joinThreshold, &secretParts);
}

/**
 * @brief Test if the threshold is bigger than the secret vector size when calling SecretSharer::join()
 */
TEST_F(SecretSharerTest, joinBiggerThreshold) {
    unsigned int splitSecretSize = 2;
    unsigned int splitParts = 2;
    unsigned int splitThreshold = 2;
    std::vector<std::ostream *> secretParts = splitSecret(splitSecretSize, splitParts, splitThreshold);

    unsigned int joinSecretSize = 2;
    unsigned int joinParts = 4;
    unsigned int joinThreshold = 3;
    testJoinInvalidParam(joinSecretSize, joinParts, joinThreshold, &secretParts);
}

TEST_F(SecretSharerTest, splitInvalidNumParts) {
    unsigned int splitSecretSize = 2;
    unsigned int splitParts = 0;
    unsigned int splitThreshold = 2;
    testSplitInvalidParam(splitSecretSize, splitParts, splitThreshold);
}

TEST_F(SecretSharerTest, splitInvalidThreshold) {
    unsigned int splitSecretSize = 2;
    unsigned int splitParts = 2;
    unsigned int splitThreshold = 0;
    testSplitInvalidParam(splitSecretSize, splitParts, splitThreshold);
}

/**
 * @brief Test if the number of parts the secret was split into is less than the threshold when calling SecretSharer::split()
 */
TEST_F(SecretSharerTest, splitLessNumParts) {
    unsigned int splitSecretSize = 4;
    unsigned int splitParts = 2;
    unsigned int splitThreshold = 4;
    testSplitInvalidParam(splitSecretSize, splitParts, splitThreshold);
}

/**
 * @brief Test if the threshold is bigger than the secret vector size when calling SecretSharer::split()
 */
TEST_F(SecretSharerTest, splitBiggerThreshold) {
    unsigned int splitSecretSize = 2;
    unsigned int splitParts = 4;
    unsigned int splitThreshold = 3;
    testSplitInvalidParam(splitSecretSize, splitParts, splitThreshold);
}
