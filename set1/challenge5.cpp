#include "crypto.hpp"
#include "gtest/gtest.h"
#include <iostream>
#include <stdexcept>

template <typename PlainIter, typename KeyIter>
bytes repeating_key_XOR(PlainIter pbeg, PlainIter pend, KeyIter kbeg, KeyIter kend)
{
    if (kbeg == kend)
    {
        throw std::logic_error("Key cannot be empty");
    }
    bytes result;
    auto key_iter = kbeg;

    for (; pbeg != pend; pbeg++)
    {
        byte key = static_cast<byte>(*key_iter++);
        result.push_back(static_cast<byte>(key ^ static_cast<byte>((*pbeg))));
        if (key_iter == kend)
            key_iter = kbeg;
    }
    return result;
}

template <typename PlainText, typename CipherText>
bytes repeating_key_XOR(const PlainText &p, const CipherText c)
{
    return repeating_key_XOR(std::begin(p), std::end(p), std::begin(c), std::end(c));
}

TEST(Challenge5, solution)
{
    std::string text = "Burning 'em, if you ain't quick and nimble\n"
                       "I go crazy when I hear a cymbal";
    std::string key = "ICE";
    std::string expected =
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a65"
        "2e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

    auto ciphertext = repeating_key_XOR(text, key);
    auto plaintext = repeating_key_XOR(ciphertext, key);
    ciphertext = hex::from_bytes(ciphertext);

    EXPECT_EQ(plaintext, bytes(text.begin(), text.end()));
    EXPECT_EQ(ciphertext, bytes(expected.begin(), expected.end()));
}

int main(int argc, char *argv[])
{
    if (argc >= 2)
    {
        if (strcmp(argv[1], "encrypt") == 0)
        {
            std::string plaintext, key, line;
            std::cout << "Enter key: ";
            std::getline(std::cin, key);
            std::cout << "Enter plaintext: (ctrl + d to stop):";

            while (std::getline(std::cin, line))
            {
                plaintext += line + '\n';
            }

            auto ciphertext = repeating_key_XOR(plaintext, key);
            ciphertext = hex::from_bytes(ciphertext);
            std::cout << "Ciphertext: " << ciphertext << std::endl;
            return 0;
        }
        else if (strcmp(argv[1], "decrypt") == 0)
        {
            std::string ciphertext, key;
            std::cout << "Enter key: ";
            std::getline(std::cin, key);
            std::cout << "Enter ciphertext (hex encoded): ";
            std::getline(std::cin, ciphertext);

            auto ciphertext_b = hex::to_bytes(ciphertext);
            auto plaintext = repeating_key_XOR(ciphertext_b, key);
            std::cout << "Plaintext: " << plaintext << std::endl;
            return 0;
        }
    }
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}