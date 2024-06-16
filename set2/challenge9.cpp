#include "crypto.hpp"
#include "gtest/gtest.h"
#include <iostream>

TEST(PKCS7, padding_empty_strings)
{
    std::string text = "";
    auto padded = pad_pkcs7(bytes(text.begin(), text.end()), 16);
    ASSERT_EQ(padded.size(), 16);
    for (int i = 0; i < 16; i++)
        ASSERT_EQ(padded[i], 16);
}

TEST(PKCS7, padding_length_of_blocksize)
{
    std::string text = "0123456789abcdef";
    auto padded = pad_pkcs7(bytes(text.begin(), text.end()), 16);
    ASSERT_EQ(padded.size(), 32);
    for (int i = 16; i < 32; i++)
        ASSERT_EQ(padded[i], 16);
}

TEST(PKCS7, padding_single_character)
{
    std::string text = "x";
    auto padded = pad_pkcs7(bytes(text.begin(), text.end()), 16);
    ASSERT_EQ(padded.size(), 16);
    for (int i = 1; i < 16; i++)
        ASSERT_EQ(padded[i], 15);
}

TEST(PKCS7, padding_multiple_characters)
{
    std::string text = "YELLOW SUBMARINE";
    auto padded = pad_pkcs7(bytes(text.begin(), text.end()), 20);
    ASSERT_EQ(padded.size(), 20);
    ASSERT_EQ(padded[16], 0x04);
    ASSERT_EQ(padded[17], 0x04);
    ASSERT_EQ(padded[18], 0x04);
    ASSERT_EQ(padded[19], 0x04);
}

int main(int argc, char *argv[])
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}