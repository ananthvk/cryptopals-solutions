#include "crypto.hpp"
#include "gtest/gtest.h"

bytes fixed_XOR(bytes &b1, bytes &b2)
{
    if (b1.size() != b2.size())
    {
        throw std::logic_error("Buffers are not of equal size");
    }
    auto b1_iter = b1.begin();
    auto b2_iter = b2.begin();
    bytes result;
    for (; b1_iter != b1.end() && b2_iter != b2.end(); ++b1_iter, ++b2_iter)
    {
        result.push_back(*b1_iter ^ *b2_iter);
    }
    return result;
}

TEST(Challenge2, solution)
{
    std::string hexstring = "1c0111001f010100061a024b53535009181c";
    auto h1 = hex::to_bytes(hexstring);
    
    hexstring = "686974207468652062756c6c277320657965";
    auto h2 = hex::to_bytes(hexstring);
    
    auto encoded = fixed_XOR(h1, h2);

    hexstring = "746865206b696420646f6e277420706c6179";
    auto expected = hex::to_bytes(hexstring);
    
    EXPECT_EQ(encoded, expected);
}

int main(int argc, char *argv[])
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}