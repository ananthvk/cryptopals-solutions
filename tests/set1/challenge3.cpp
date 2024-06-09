#include "crypto.hpp"
#include "gtest/gtest.h"

// Contains the frequency distribution for letters in english,
// characters with lower index are more frequent
static std::string frequency_dist = " etaoinshrdlcumwfgypbvkjxqz";

static int score_table[256] = {0};

// This function must be called before using score_table
void build_score_table()
{
    for (int i = 0; i < 256; i++)
    {
        if (isalnum(i) || isspace(i))
            score_table[i] = 1;
        else
            score_table[i] = -1;
    }
    int i = static_cast<int>(frequency_dist.size());
    for (const auto &ch : frequency_dist)
    {
        score_table[static_cast<byte>(ch)] = i;
        score_table[static_cast<byte>(toupper(ch))] = i;
        --i;
    }
}

// Calculates a score for a sequence of bytes
// Higher the score, higher the probability that it is a piece of english text
// If a non alphanumeric character is found, the score is reduced

bool is_special_or_digit(byte ch)
{
    // Assuming ASCII
    return ('0' <= ch && ch <= '9') || (33 <= ch && ch <= 64) || (91 <= ch && ch <= 96) ||
           (123 <= ch && ch <= 126);
}

int calculate_score(bytes &text)
{
    int final_score = 0;
    int num_special = 0;
    for (const auto &ch : text)
    {
        final_score += score_table[ch];
        num_special += is_special_or_digit(ch);
    }
    // To remove all the minus ones
    final_score += num_special;

    return final_score;
}

bytes single_byte_XOR(const bytes &plaintext, byte key)
{
    bytes ciphertext;
    ciphertext.reserve(plaintext.size());
    for (const auto &b : plaintext)
    {
        ciphertext.push_back(b ^ key);
    }
    return ciphertext;
}

TEST(Challenge3, solution)
{
    build_score_table();

    std::string hexstring = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    auto byts = hex::to_bytes(hexstring);

    int max_score = 0;
    bytes english_plaintext;
    int key = 0;

    // Brute force, check all the bytes and print the one with the highest english score
    for (int i = 0; i < 256; i++)
    {
        auto plaintext = single_byte_XOR(byts, static_cast<byte>(i));
        int score = calculate_score(plaintext);
        if (score > max_score)
        {
            max_score = score;
            english_plaintext = plaintext;
            key = i;
        }
    }

    std::string plaintext;
    std::copy(english_plaintext.begin(), english_plaintext.end(), std::back_inserter(plaintext));

    EXPECT_EQ(key, 'X');
    EXPECT_EQ(plaintext, "Cooking MC's like a pound of bacon");
}

int main(int argc, char *argv[])
{
    // To ecrypt custom strings, here is a small python snippet
    // message = b'Never forget what you are, for surely the world will not.'
    // key = '@'
    // cipher = bytes([i ^ ord(key) for i in message]).hex()
    build_score_table();
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}