#include "crypto.hpp"
#include "gtest/gtest.h"


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