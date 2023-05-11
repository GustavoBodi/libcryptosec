#include <libcryptosec/ByteArray.h>

#include <sstream>
#include <gtest/gtest.h>
#include <utility>
#include <memory>


/**
 * @brief Testes unitários da classe ByteArray.
 */
class ByteArrayTest : public ::testing::Test {

protected:
    using BytePair = std::pair<ByteArray, ByteArray>;

    virtual void SetUp() {
    }

    virtual void TearDown() {
    }

    BytePair generateFromStream() {
        std::ostringstream oss;
        oss.str(ByteArrayTest::stringASCII);
        ByteArray ba_stream(&oss);
        ByteArray copy = ba_stream;
        return std::make_pair(ba_stream, copy);
    }

    BytePair generateFromString() {
        ByteArray ba_str(ByteArrayTest::stringASCII);
        ByteArray copy = ba_str;
        return std::make_pair(ba_str, copy);
    }

    BytePair generateFromUnsigned() {
        auto uchar = chr;
        ByteArray ba_unsigned{uchar, size};
        ByteArray copy{ba_unsigned};
        return std::make_pair(ba_unsigned, copy);
    }

    BytePair generateFromPointers() {
        ByteArray ba_pnt;

        auto chr_pnt = new unsigned char[size];
        memcpy(chr_pnt, ByteArrayTest::chr, ByteArrayTest::size);
        ba_pnt.setDataPointer(chr_pnt, ByteArrayTest::size);
        ByteArray copy = ba_pnt;
        return std::make_pair(ba_pnt, copy);
    }

    BytePair generateFromCharCopy() {
        ByteArray ba_cp;

        auto chr_cp = make_unique<unsigned char[]>(ByteArrayTest::size);
        memcpy(chr_cp.get(), ByteArrayTest::chr, ByteArrayTest::size);
        ba_cp.copyFrom(chr_cp.get(), ByteArrayTest::size);
        ByteArray copy = ba_cp;
        return std::make_pair(ba_cp, copy);
    }

    void testThrowInvalid() {
        ByteArray ba;
        ASSERT_THROW(ba[0], out_of_range);
        ASSERT_THROW(ba.at(0), out_of_range);
    }

    void testHexSeparator() {
        ByteArray ba{simpleASCII};
        ASSERT_EQ(ba.toHex('-'), ByteArrayTest::simpleHexSeparator);
    }

    void testCompareString(BytePair ba_pair) {
        ASSERT_EQ(ba_pair.first.toString(), ba_pair.second.toString());
        ASSERT_EQ(ba_pair.first.toString(), stringASCII);
    }

    void testCompareHex(BytePair ba_pair) {
        ASSERT_EQ(ba_pair.first.toHex(), ba_pair.second.toHex());
        ASSERT_EQ(ba_pair.first.toHex(), stringHex);
    }

    void testCompareEqual(BytePair ba_pair) {
        ASSERT_EQ(ba_pair.first, ba_pair.second);
    }

    void testOverloadedEquals(BytePair ba_pair) {
        ASSERT_TRUE(ba_pair.first == ba_pair.second);
    }

    void testOverloadedDifferent(BytePair ba_pair) {
        ASSERT_FALSE(ba_pair.first != ba_pair.second);
    }

    void testStreamToString(BytePair ba_pair) {
        unique_ptr<std::istringstream> iss{ba_pair.first.toStream()};
        ASSERT_EQ(iss->str(), ba_pair.second.toString());
        ASSERT_EQ(iss->str(), stringASCII);
    }

    void testSize(BytePair ba_pair) {
        ASSERT_EQ(ba_pair.first.size(), ba_pair.second.size());
        ASSERT_EQ(ba_pair.first.size(), size);
    }

    void testChar(BytePair ba_pair) {
        ASSERT_EQ(ba_pair.first.at(10), ba_pair.second.at(10));
        ASSERT_EQ(ba_pair.second.at(10), compChar);
    }

    void testGeneric(BytePair pair) {
        testCompareString(pair);
        testCompareHex(pair);
        testCompareEqual(pair);
        testOverloadedDifferent(pair);
        testOverloadedEquals(pair);
        testStreamToString(pair);
        testSize(pair);
        testChar(pair);
    }

    static std::string simpleASCII;
    static std::string simpleHex;
    static std::string simpleHexSeparator;
    static std::string stringASCII;
    static std::string stringHex;
    static const char compChar;
    static unsigned char chr[];
    static unsigned int size;

};

/*
 * Initialization of variables used in the tests
 */
std::string ByteArrayTest::simpleASCII{"Simple"};
std::string ByteArrayTest::simpleHex{"53696D706C65"};
std::string ByteArrayTest::simpleHexSeparator{"53-69-6D-70-6C-65"};
std::string ByteArrayTest::stringASCII{"I found it! Silksong release date is [redacted]"};
std::string ByteArrayTest::stringHex{
        "4920666F756E64206974212053696C6B736F6E672072656C656173652064617465206973205B72656461637465645D"};
const char ByteArrayTest::compChar{'!'};
unsigned char ByteArrayTest::chr[]{"I found it! Silksong release date is [redacted]"};
unsigned int ByteArrayTest::size{47};


TEST_F(ByteArrayTest, CompareString) {
    BytePair pair{generateFromString()};
    testCompareString(pair);
}

TEST_F(ByteArrayTest, CompareHex) {
    BytePair pair{generateFromString()};
    testCompareHex(pair);
}

TEST_F(ByteArrayTest, CompareEqual) {
    BytePair pair{generateFromString()};
    testCompareEqual(pair);
}

TEST_F(ByteArrayTest, OverloadedDifferent) {
    BytePair pair{generateFromString()};
    testOverloadedDifferent(pair);
}

TEST_F(ByteArrayTest, OverloadedEquals) {
    BytePair pair{generateFromString()};
    testOverloadedEquals(pair);
}

TEST_F(ByteArrayTest, StreamToString) {
    BytePair pair{generateFromString()};
    testStreamToString(pair);
}

TEST_F(ByteArrayTest, Size) {
    BytePair pair{generateFromString()};
    testSize(pair);
}

TEST_F(ByteArrayTest, Char) {
    BytePair pair{generateFromString()};
    testChar(pair);
}

TEST_F(ByteArrayTest, FromStr) {
    BytePair pair{generateFromString()};
    testGeneric(pair);
}

TEST_F(ByteArrayTest, FromUnsigned) {
    BytePair pair{generateFromUnsigned()};
    testGeneric(pair);
}

TEST_F(ByteArrayTest, FromStream) {
    BytePair pair{generateFromStream()};
    testGeneric(pair);
}

TEST_F(ByteArrayTest, FromPointer) {
    BytePair pair{generateFromPointers()};
    testGeneric(pair);
}

TEST_F(ByteArrayTest, FromCopiedChar) {
    BytePair pair{generateFromCharCopy()};
    testGeneric(pair);
}

TEST_F(ByteArrayTest, TestThrow) {
    testThrowInvalid();
}

TEST_F(ByteArrayTest, TestHexSeparator) {
    testHexSeparator();
}
