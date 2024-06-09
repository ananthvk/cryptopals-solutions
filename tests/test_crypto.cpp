#include "crypto.hpp"
#include "gtest/gtest.h"

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
}

int main(int argc, char *argv[])
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}