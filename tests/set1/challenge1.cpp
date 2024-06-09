#include "crypto.hpp"
#include "gtest/gtest.h"

TEST(Challenge1, solution)
{
    std::string hexstring = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f"
                            "6e6f7573206d757368726f6f6d";
    auto result = base64::from_bytes(hex::to_bytes(hexstring));
    std::string encoded;
    std::copy(result.begin(), result.end(), std::back_inserter(encoded));
    ASSERT_EQ(encoded, "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
}

int main(int argc, char *argv[])
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}