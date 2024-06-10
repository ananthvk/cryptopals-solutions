#include "crypto.hpp"
#include "gtest/gtest.h"

TEST(Hex, from_bytes_empty) { EXPECT_EQ(hex::from_bytes(bytes()), bytes()); }

TEST(Hex, from_bytes)
{
    bytes b = {132, 15, 0, 1, 4, 12, 13, 255};
    bytes expected = {'8', '4', '0', 'f', '0', '0', '0', '1', '0', '4', '0', 'c', '0', 'd', 'f', 'f'};
    auto hexed = hex::from_bytes(b);
    EXPECT_EQ(hexed, expected);
}

TEST(Hex, to_bytes_empty) { EXPECT_EQ(hex::to_bytes(std::string("")), bytes()); }

TEST(Hex, to_bytes_error)
{
    EXPECT_THROW(hex::to_bytes(std::string("abx")), std::runtime_error);
    EXPECT_THROW(hex::to_bytes(std::string("abb")), std::runtime_error);
}

TEST(Hex, to_bytes)
{
    EXPECT_EQ(hex::to_bytes(std::string("ff"))[0], 255);

    std::string s = "0affe2";
    bytes expected = {10, 255, 226};
    auto result = hex::to_bytes(s);
    EXPECT_EQ(result, expected);

    s = "00aae20fbcae01234567890abcdeff";
    expected = {0, 170, 226, 15, 188, 174, 1, 35, 69, 103, 137, 10, 188, 222, 255};
    result = hex::to_bytes(s);
    EXPECT_EQ(result, expected);

    s = "000102030405060708090a0b0c0d0e0f";
    expected = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    result = hex::to_bytes(s);
    EXPECT_EQ(result, expected);

    result = hex::to_bytes(s.begin(), s.begin() + 4);
    expected = {0, 1};
    EXPECT_EQ(result, expected);
}

TEST(Base64, from_bytes_empty) { EXPECT_EQ(hex::to_bytes(std::string("")), bytes()); }

TEST(Base64, from_bytes_simple)
{
    std::string s = "Man";
    bytes expected = {'T', 'W', 'F', 'u'};
    auto result = base64::from_bytes(s);
    EXPECT_EQ(result, expected);

    s = "M";
    expected = {'T', 'Q', '=', '='};
    result = base64::from_bytes(s);
    EXPECT_EQ(result, expected);

    s = "Ma";
    expected = {'T', 'W', 'E', '='};
    result = base64::from_bytes(s);
    EXPECT_EQ(result, expected);

    s = "The quick brown fox jumps over the lazy dogs";
    expected = {86,  71,  104, 108, 73,  72,  70,  49,  97,  87,  78,  114, 73,  71,  74,
                121, 98,  51,  100, 117, 73,  71,  90,  118, 101, 67,  66,  113, 100, 87,
                49,  119, 99,  121, 66,  118, 100, 109, 86,  121, 73,  72,  82,  111, 90,
                83,  66,  115, 89,  88,  112, 53,  73,  71,  82,  118, 90,  51,  77,  61};
    result = base64::from_bytes(s);
    EXPECT_EQ(result, expected);

    bytes b = {0};
    expected = {'A', 'A', '=', '='};
    result = base64::from_bytes(b);
    EXPECT_EQ(result, expected);
}

int main(int argc, char *argv[])
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}