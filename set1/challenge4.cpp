#include "crypto.hpp"
#include <fstream>
#include <iostream>
#include <iterator>

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

bytes decode(const std::string &hexstring, int &key, int &calculated_score)
{
    auto byts = hex::to_bytes(hexstring);
    int max_score = 0;
    bytes english_plaintext;

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

    calculated_score = max_score;
    return english_plaintext;
}

int main(int argc, char *argv[])
{
    std::string filename;
    if (argc != 2)
    {
        filename = "challenge4.txt";
    }
    else
    {
        filename = argv[1];
    }
    std::ifstream ifs(filename);
    if (!ifs)
    {
        std::cout << "Could not open " << filename << std::endl;
        return 1;
    }
    build_score_table();
    std::string line;

    int max_score = 0;
    int max_score_key = 0;
    bytes possible_plaintext;
    std::string possible_ciphertext;

    while (std::getline(ifs, line))
    {
        int key = 0, score = 0;
        auto decoded = decode(line, key, score);
        if (score > max_score)
        {
            max_score = score;
            max_score_key = key;
            possible_plaintext = decoded;
            possible_ciphertext = line;
        }
    }
    std::cout << "Among the given lines, " << std::endl;
    std::cout << possible_ciphertext << std::endl;
    std::cout << "Is likely to be XOR encrypted with key " << max_score_key << " and has a score "
              << max_score << std::endl;
    std::cout << "Plaintext: ";
    std::copy(possible_plaintext.begin(), possible_plaintext.end(),
              std::ostream_iterator<byte>(std::cout));
    std::cout << std::endl;
}
