#include <libcryptosec/BigInteger.h>

#include <sstream>
#include <gtest/gtest.h>
#include <utility>


/**
 * @brief Testes unitários da classe BigInteger.
 */
class BigIntegerTest : public ::testing::Test {

protected:
    /**
     * @brief Tipo de uso interno para teste em pares
     */
    using BintPair = std::pair<BigInteger, BigInteger>;

    virtual void SetUp() {
    }

    virtual void TearDown() {
    }

    /**
     * @brief Atribui para ambos os valores da representação intermediário do par um valor
     */
    void pairSetLong(BintPair &pair) {
        pair.first.setValue(longValue);
        pair.second.setValue(longValue);
    }

    /**
     * @brief Atribui para ambos os valores da representação intermediário do par um valor negativo
     */
    void pairSetLongNeg(BintPair &pair) {
        pair.first.setValue(longValueNeg);
        pair.second.setValue(longValueNeg);
    }

    /**
     * @brief Cria uma par a partir de uma BigInteger vazia e o copia para outro BigInteger
     */
    BintPair CreatePairFromEmpty() {
        BigInteger bi_empty = BigInteger();
        BigInteger copy{bi_empty};
        return std::make_pair(bi_empty, copy);
    }

    /**
     * @brief Cria uma par a partir do construtor default com valores dados
     */
    BintPair CreatePairFromDefault() {
        BigInteger bi_default{longValue};
        BigInteger copy{bi_default};
        return std::make_pair(bi_default, copy);
    }

    /**
     * @brief Cria um par de BigInteger a partir de uma BigInteger do OpenSSL
     */
    BintPair CreatePairFromBigNum() {
        BIGNUM *p = BN_new();
        BN_bin2bn((unsigned char *) "\x01\x02\x03", 3, p);
        BigInteger bi_bignum{p};
        BigInteger copy{bi_bignum};
        return std::make_pair(bi_bignum, copy);
    }

    /**
     * @brief Cria um par de BigInteger a partir de um ASN1_INTEGER do OPENSSL
     */
    BintPair CreatePairFromASN1() {
        ASN1_INTEGER *ans_int = ASN1_INTEGER_new();
        ASN1_INTEGER_set(ans_int, longValue);
        BigInteger bi_ans1{ans_int};
        BigInteger copy{bi_ans1};
        return std::make_pair(bi_ans1, copy);
    }

    /**
     * @brief Cria um par a partir de uma String
     */
    BintPair CreatePairFromString() {
        BigInteger bi_str{decValue};
        BigInteger copy{bi_str};
        return std::make_pair(bi_str, copy);
    }

    /**
     * @brief Cria um par a partir de um ByteArray
     */
    BintPair CreatePairFromByteArray() {
        BigInteger bi{longValue};
        ByteArray ba{*bi.getBinValue()};
        BigInteger bi_ba{ba};
        BigInteger copy{bi_ba};
        return std::make_pair(bi_ba, copy);
    }

    /**
     * @brief Cria um par a partir de um BigInteger
     */
    BintPair CreatePairFromBigInteger() {
        BigInteger bi{longValue};
        BigInteger biFromRef{bi};
        BigInteger copy{biFromRef};
        return std::make_pair(biFromRef, copy);
    }

    /**
     * @brief Testa todas as operações para os respectivos construtores
     */
    void testGeneric(BintPair pair) {
        testGetValue(pair);
        testIsNegative(pair);
        testGetASN1(pair);
        testGetBinValue(pair);
        testGetBigNum(pair);
        testToHex(pair);
        testToDec(pair);
        testSetHexValue(pair);
        testSetDec(pair);
        testSetRandValue(pair);
        testSetValue(pair);
        testSize(pair);
        testSum(pair);
        testSumBint(pair);
        testSumBintOverload(pair);
        testSumOverload(pair);
        testSub(pair);
        testSubOverload(pair);
        testSubBintOverload(pair);
        testCompare(pair);
        testEquals(pair);
        testDifferent(pair);
        testToDecNeg(pair);
        testToHexNeg(pair);
        testSetDecNeg(pair);
        testSetHexValueNeg(pair);
        testGetASN1Neg(pair);
        testGetValueNeg(pair);
        testGetBinValueNeg(pair);
    }

    /**
     * @brief Testa se o valor do Getter corresponde ao esperado
     */
    void testGetValue(BintPair pair) {
        pairSetLong(pair);
        ASSERT_EQ(pair.first.getValue(), pair.second.getValue());
        ASSERT_EQ(pair.first.getValue(), longValue);
    }

    /**
     * @brief Testa se o valor do Getter para valores negativos corresponde ao esperado
     */
    void testGetValueNeg(BintPair pair) {
        pairSetLongNeg(pair);
        ASSERT_EQ(pair.first.getValue(), pair.second.getValue());
        ASSERT_EQ(pair.first.getValue(), longValueNeg);
    }

    /**
     * @brief Testa o método que indica se o valor é negativo
     */
    void testIsNegative(BintPair pair) {
        pair.first.setValue(longValueNeg);
        pair.second.setValue(longValue);
        ASSERT_TRUE(pair.first.isNegative());
        ASSERT_TRUE(!pair.second.isNegative());
    }

    /**
     * @brief Testa o Getter que converte o valor para ASN1
     */
    void testGetASN1(BintPair pair) {
        ASN1_INTEGER *ans_int = ASN1_INTEGER_new();
        ASN1_INTEGER_set(ans_int, longValue);
        pairSetLong(pair);
        int64_t *first = new int64_t;
        int64_t *ans = new int64_t;
        ASN1_INTEGER_get_int64(first, pair.first.getASN1Value());
        ASN1_INTEGER_get_int64(ans, ans_int);
        ASSERT_EQ(*first, *ans);

        int64_t *part1 = new int64_t;
        int64_t *part2 = new int64_t;
        ASN1_INTEGER_get_int64(part1, pair.first.getASN1Value());
        ASN1_INTEGER_get_int64(part2, pair.second.getASN1Value());
        ASSERT_EQ(*part1, *part2);
    }

    /**
     * @brief Testa o Getter que converte o valor para ASN1 para valores negativos
     */
    void testGetASN1Neg(BintPair pair) {
        pairSetLongNeg(pair);
        ASN1_INTEGER *ans_int_2 = ASN1_INTEGER_new();
        ASN1_INTEGER_set(ans_int_2, longValueNeg);
        int64_t *part3 = new int64_t;
        int64_t *part4 = new int64_t;
        ASN1_INTEGER_get_int64(part3, pair.first.getASN1Value());
        ASN1_INTEGER_get_int64(part4, ans_int_2);
        ASSERT_EQ(*part3, *part4);
    }

    /**
     * @brief Testa o Getter de valores Bin
     */
    void testGetBinValue(BintPair pair) {
        BigInteger bi;
        ASSERT_EQ(0, bi.getValue());
        ASSERT_EQ(0, bi.size());

        pairSetLong(pair);
        ByteArray *ba = pair.first.getBinValue();
        BigInteger biTest(*ba);
        ASSERT_EQ(pair.first.getValue(), biTest.getValue());
    }

    /**
     * @brief Testa o Getter de valores Bin negativos
     */
    void testGetBinValueNeg(BintPair pair) {
        BigInteger bi;
        ASSERT_EQ(0, bi.getValue());
        ASSERT_EQ(0, bi.size());

        pair.second.setValue(longValueNeg);
        ByteArray *ba = pair.second.getBinValue();
        BigInteger biTestNeg(*ba);
        ASSERT_EQ(pair.second.getValue(), biTestNeg.getValue());
    }

    /**
     * @brief Testa o Getter para BigNums do OpenSSL
     */
    void testGetBigNum(BintPair pair) {
        pairSetLong(pair);
        auto res = BN_bn2dec(pair.first.getBIGNUM());
        auto res2 = BN_bn2dec(pair.second.getBIGNUM());
        ASSERT_EQ(*res, *res2);

        auto bi = BigInteger();
        bi.setValue(BigIntegerTest::longValue);
        const BIGNUM *bn = bi.getBIGNUM();
        auto chr = BN_bn2dec(bn);
        ASSERT_EQ(BigIntegerTest::decValue, chr);
    }

    /**
     * @brief Testa a conversão para Hexadecimal
     */
    void testToHex(BintPair pair) {
        pairSetLong(pair);
        ASSERT_EQ(pair.first.toHex(), pair.second.toHex());
        ASSERT_EQ(pair.first.toHex(), hexValue);
        ASSERT_EQ(pair.second.toHex(), hexValue);
    }

    /**
     * @brief Testa a conversão para Hexadecimais Negativos
     */
    void testToHexNeg(BintPair pair) {
        pairSetLongNeg(pair);
        ASSERT_EQ(pair.first.toHex(), pair.second.toHex());
        ASSERT_EQ(pair.first.toHex(), hexValueNeg);
        ASSERT_EQ(pair.second.toHex(), hexValueNeg);
    }

    /**
     * @brief Testa a conversão para valores Decimais
     */
    void testToDec(BintPair pair) {
        pairSetLong(pair);
        ASSERT_EQ(pair.first.toDec(), pair.second.toDec());
        ASSERT_EQ(pair.first.toDec(), decValue);
        ASSERT_EQ(pair.second.toDec(), decValue);
    }

    /**
     * @brief Testa a conversão para valores Decimais Negativos
     */
    void testToDecNeg(BintPair pair) {
        pairSetLongNeg(pair);
        ASSERT_EQ(pair.first.toDec(), pair.second.toDec());
        ASSERT_EQ(pair.first.toDec(), decValueNeg);
        ASSERT_EQ(pair.second.toDec(), decValueNeg);
    }

    /**
     * @brief Testa se o Setter para valores hexadecimais funciona
     */
    void testSetHexValue(BintPair pair) {
        pair.first.setHexValue(hexValue);
        pair.second.setHexValue(hexValue);
        ASSERT_EQ(pair.first, pair.second);
        ASSERT_EQ(pair.first.toHex(), hexValue);
        ASSERT_EQ(pair.second.toHex(), hexValue);
    }

    /**
     * @brief Testa se o Setter para valores hexadecimais negativos funciona
     */
    void testSetHexValueNeg(BintPair pair) {
        pair.first.setHexValue(hexValueNeg);
        pair.second.setHexValue(hexValueNeg);
        ASSERT_EQ(pair.first, pair.second);
        ASSERT_EQ(pair.first.toHex(), hexValueNeg);
        ASSERT_EQ(pair.second.toHex(), hexValueNeg);
    }

    /**
     * @brief Testa se o Setter para valores Decimais funciona
     */
    void testSetDec(BintPair pair) {
        pair.first.setDecValue(decValue);
        pair.second.setDecValue(decValue);
        ASSERT_EQ(pair.first, pair.second);
        ASSERT_EQ(pair.first, decValue);
        ASSERT_EQ(pair.second, decValue);
    }

    /**
     * @brief Testa se o Setter para valores Decimais Negativos funciona
     */
    void testSetDecNeg(BintPair pair) {
        pair.first.setDecValue(decValueNeg);
        pair.second.setDecValue(decValueNeg);
        ASSERT_EQ(pair.first, pair.second);
        ASSERT_EQ(pair.first, decValueNeg);
        ASSERT_EQ(pair.second, decValueNeg);
    }

    /**
     * @brief Testa a geração aleatória de números (por acaso do destino pode falhar)
     */
    void testSetRandValue(BintPair pair) {
        pair.first.setRandValue(size);
        pair.second.setRandValue(size);
        ASSERT_FALSE(pair.first == pair.second);
        ASSERT_TRUE(pair.first.getValue() != 0);
    }

    /**
     * @brief Testa o Setter para os valores dados
     */
    void testSetValue(BintPair pair) {
        pair.first.setValue(longValue);
        ASSERT_EQ(pair.first, longValue);
        pair.first.setValue(longValueNeg);
        ASSERT_EQ(pair.first, longValueNeg);
        pair.second.setValue(longValueNeg);
        ASSERT_EQ(pair.first.getValue(), pair.second.getValue());
    }

    /**
     * @brief Testa se o tamanho da representação interna corresponde ao esperado
     */
    void testSize(BintPair pair) {
        pairSetLong(pair);
        ASSERT_EQ(pair.first.size(), pair.second.size());
        pair.second.setValue(longValueNeg);
        ASSERT_EQ(pair.first.size(), size);
        ASSERT_EQ(pair.second.size(), sizeNeg);
    }

    /**
     * @brief Testa se o soma para o tipo funciona corretamente
     */
    void testSum(BintPair pair) {
        pairSetLong(pair);
        pair.first = pair.first + 2;
        ASSERT_EQ(pair.first.getValue(), longValue + 2);
        ASSERT_TRUE(pair.first.getValue() == (pair.second + 2).getValue());
    }

    /**
     * @brief Testa se a soma entre tipos funciona corretamente
     */
    void testSumBint(BintPair pair) {
        pair.first = 1;
        pair.second = 10;
        ASSERT_TRUE(pair.first + pair.second == 11);
    }

    /**
     * @brief Testa se o operador de soma overloaded funciona corretamente
     */
    void testSumOverload(BintPair pair) {
        pairSetLong(pair);
        pair.first += 10;
        ASSERT_EQ(pair.first.getValue(), pair.first.getValue() + 10);
        ASSERT_TRUE(pair.first.getValue() == pair.second.getValue() + 10);
    }

    /**
     * @brief Testa se a soma entre overloadeds funciona corretamente
     */
    void testSumBintOverload(BintPair pair) {
        pair.first = 1;
        pair.second = 10;
        pair.first += pair.second;
        ASSERT_EQ(pair.first, 11);
        ASSERT_EQ(pair.second, 10);
    }

    /**
     * @brief Testa se a subtração funciona corretamente
     */
    void testSub(BintPair pair) {
        pairSetLong(pair);
        pair.first += -2;
        ASSERT_EQ(pair.first.getValue(), longValue - 2);
        ASSERT_TRUE(pair.first.getValue() == (pair.second - 2).getValue());
    }

    /**
     * @brief Testa se a subtração Overloaded funciona corretamente
     */
    void testSubOverload(BintPair pair) {
        pairSetLong(pair);
        pair.first -= 1;
        ASSERT_EQ(pair.first.getValue(), longValue - 1);
        ASSERT_TRUE(pair.first.getValue() == (pair.second).getValue() - 1);
    }

    /**
     * @brief Testa se a subtração entre os tipos overloaded funciona corretamente
     */
    void testSubBintOverload(BintPair pair) {
        pair.first = 1;
        pair.second = 10;
        pair.first -= pair.second;
        ASSERT_EQ(pair.first, -9);
        ASSERT_EQ(pair.second, 10);
    }

    /**
     * @brief Testa se o método compare corresponde ao esperado
     */
    void testCompare(BintPair pair) {
        pairSetLong(pair);
        ASSERT_EQ(pair.first.compare(pair.second), 0);
        pair.second += 1;
        ASSERT_EQ(pair.first.compare(pair.second), -1);
        pair.second += -2;
        ASSERT_EQ(pair.first.compare(pair.second), 1);
    }

    /**
     * @brief Testa se o operador overloaded de igual funciona
     */
    void testEquals(BintPair pair) {
        pairSetLong(pair);
        ASSERT_TRUE(pair.first == pair.second);
    }

    /**
     * @brief Testa se o operador overloaded de diferente funciona corretamente
     */
    void testDifferent(BintPair pair) {
        pairSetLong(pair);
        pair.first += 1;
        ASSERT_TRUE(pair.first != pair.second);
    }


    static long longValue;
    static long longValueNeg;
    static int size;
    static int sizeNeg;
    static std::string decValue;
    static std::string decValueNeg;
    static std::string hexValue;
    static std::string hexValueNeg;
};

/*
 * Initialization of variables used in the tests
 */
long BigIntegerTest::longValue{1234567890987654321};
long BigIntegerTest::longValueNeg{-1234567890987654321};
int BigIntegerTest::size{61};
int BigIntegerTest::sizeNeg{61};
std::string BigIntegerTest::decValue{"1234567890987654321"};
std::string BigIntegerTest::decValueNeg{"-1234567890987654321"};
std::string BigIntegerTest::hexValue{"112210F4B16C1CB1"};
std::string BigIntegerTest::hexValueNeg{"-112210F4B16C1CB1"};

/**
 * @brief Tests if Default Constructor creates a BigInteger with value zero
 */
TEST_F(BigIntegerTest, GetValue) {
    auto pair = CreatePairFromEmpty();
    testGetValue(pair);
}

TEST_F(BigIntegerTest, GetValueNeg) {
    auto pair = CreatePairFromEmpty();
    testGetValueNeg(pair);
}

TEST_F(BigIntegerTest, IsNegative) {
    auto pair = CreatePairFromEmpty();
    testIsNegative(pair);
}

TEST_F(BigIntegerTest, GetASN1) {
    auto pair = CreatePairFromEmpty();
    testGetASN1(pair);
}

TEST_F(BigIntegerTest, GetASN1Neg) {
    auto pair = CreatePairFromEmpty();
    testGetASN1Neg(pair);
}

TEST_F(BigIntegerTest, GetBinValue) {
    auto pair = CreatePairFromEmpty();
    testGetBinValue(pair);
}

TEST_F(BigIntegerTest, GetBinValueNeg) {
    auto pair = CreatePairFromEmpty();
    testGetBinValueNeg(pair);
}

TEST_F(BigIntegerTest, GetBigNum) {
    auto pair = CreatePairFromEmpty();
    testGetBigNum(pair);
}

TEST_F(BigIntegerTest, ToHex) {
    auto pair = CreatePairFromEmpty();
    testToHex(pair);
}

TEST_F(BigIntegerTest, ToDec) {
    auto pair = CreatePairFromEmpty();
    testToDec(pair);
}

TEST_F(BigIntegerTest, SetHex) {
    auto pair = CreatePairFromEmpty();
    testSetHexValue(pair);
}

TEST_F(BigIntegerTest, SetDec) {
    auto pair = CreatePairFromEmpty();
    testSetDec(pair);
}

TEST_F(BigIntegerTest, SetRand) {
    auto pair = CreatePairFromEmpty();
    testSetRandValue(pair);
}

TEST_F(BigIntegerTest, SetValue) {
    auto pair = CreatePairFromEmpty();
    testSetValue(pair);
}

TEST_F(BigIntegerTest, ToDecNeg) {
    auto pair = CreatePairFromEmpty();
    testToDecNeg(pair);
}

TEST_F(BigIntegerTest, ToHexNeg) {
    auto pair = CreatePairFromEmpty();
    testToHexNeg(pair);
}

TEST_F(BigIntegerTest, SetDecNeg) {
    auto pair = CreatePairFromEmpty();
    testSetDecNeg(pair);
}

TEST_F(BigIntegerTest, SetHexValueNeg) {
    auto pair = CreatePairFromEmpty();
    testSetHexValueNeg(pair);
}

TEST_F(BigIntegerTest, Size) {
    auto pair = CreatePairFromEmpty();
    testSize(pair);
}

TEST_F(BigIntegerTest, Sum) {
    auto pair = CreatePairFromEmpty();
    testSum(pair);
}

TEST_F(BigIntegerTest, SumBint) {
    auto pair = CreatePairFromEmpty();
    testSumBint(pair);
}

TEST_F(BigIntegerTest, SumBintOverload) {
    auto pair = CreatePairFromEmpty();
    testSumBintOverload(pair);
}

TEST_F(BigIntegerTest, SumOverload) {
    auto pair = CreatePairFromEmpty();
    testSumOverload(pair);
}

TEST_F(BigIntegerTest, Sub) {
    auto pair = CreatePairFromEmpty();
    testSub(pair);
}

TEST_F(BigIntegerTest, SubOverload) {
    auto pair = CreatePairFromEmpty();
    testSubOverload(pair);
}

TEST_F(BigIntegerTest, Compare) {
    auto pair = CreatePairFromEmpty();
    testCompare(pair);
}

TEST_F(BigIntegerTest, Equals) {
    auto pair = CreatePairFromEmpty();
    testEquals(pair);
}

TEST_F(BigIntegerTest, Different) {
    auto pair = CreatePairFromEmpty();
    testDifferent(pair);
}

TEST_F(BigIntegerTest, EmptyConstructor) {
    auto pair = CreatePairFromEmpty();
    testGeneric(pair);
}

TEST_F(BigIntegerTest, ASN1Constructor) {
    auto pair = CreatePairFromASN1();
    testGeneric(pair);
}

TEST_F(BigIntegerTest, BigIntegerConstructor) {
    auto pair = CreatePairFromBigInteger();
    testGeneric(pair);
}

TEST_F(BigIntegerTest, BigNumConstructor) {
    auto pair = CreatePairFromBigNum();
    testGeneric(pair);
}

TEST_F(BigIntegerTest, DefaultConstructor) {
    auto pair = CreatePairFromDefault();
    testGeneric(pair);
}

TEST_F(BigIntegerTest, StringConstructor) {
    auto pair = CreatePairFromString();
    testGeneric(pair);
}

TEST_F(BigIntegerTest, ByteArrayConstructor) {
    auto pair = CreatePairFromByteArray();
    testGeneric(pair);
}
