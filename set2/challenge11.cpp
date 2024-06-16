#include "crypto.hpp"
#include "gtest/gtest.h"
#include <assert.h>
#include <iostream>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <random>
#include <set>
#include <string>

// To detect if ECB is used, generate a plaintext which contains only a single character, eg A, of
// length atleast 3 blocks Eg: AAAAAAAAAAAAAAAAAAAAAA.....AAAAAA Now, the encryption_oracle encrypts
// the plaintext, by adding 5-10 characters before and after, say 4 characters were added before and
// 8 characters after Now the plaintext looks like: XYZZAAAAAAAAAAAA AAA...AAAA AAA...AAA
// AAAAAAAA12345678 If any two blocks of the ciphertext are same, then ECB was used, otherwise CBC
// was used.


// In the worst case, 5 characters can be added before, and 5 characters after, so 11 + 11 = 22
// characters are used for the first and last blocks. For two identical blocks, we require 16 + 16 =
// 32 characters, so 44 A's are sufficient to solve the problem

enum EncryptionMode
{
    ECB,
    CBC
};

bytes generate_bytes(int length)
{
    static std::random_device dev;
    static std::mt19937 rng(dev());
    static std::uniform_int_distribution<int> dist(0, 255);

    bytes result;
    result.reserve(length);
    for (int i = 0; i < length; i++)
        result.push_back(static_cast<byte>(dist(rng)));
    return result;
}

bytes random_encrypter(const bytes &raw_plaintext, EncryptionMode &mode)
{
    static std::random_device dev;
    static std::mt19937 rng(dev());
    std::uniform_int_distribution<int> dist01(0, 1);

    std::uniform_int_distribution<int> bytes_to_add(5, 10);
    int bytes_before = bytes_to_add(rng);
    int bytes_after = bytes_to_add(rng);

    bytes plaintext;
    bytes t = generate_bytes(bytes_before);
    plaintext.insert(plaintext.end(), t.begin(), t.end());
    plaintext.insert(plaintext.end(), raw_plaintext.begin(), raw_plaintext.end());
    t = generate_bytes(bytes_after);
    plaintext.insert(plaintext.end(), t.begin(), t.end());

    bytes key = generate_bytes(16);

    if (dist01(rng) == 0)
    {
        mode = ECB;
        return aes128_encrypt_ecb(plaintext, key);
    }
    else
    {
        mode = CBC;
        bytes iv = generate_bytes(16);
        return aes128_encrypt_cbc(plaintext, key, iv);
    }
}

// Takes a sequence of bytes as input and determines whether the ciphertext was encrypted using ECB
// or CBC
// Note the plaintext must contain atleast two identical blocks for this to work
EncryptionMode oracle(const bytes &ciphertext)
{
    size_t counts = 0;
    // If two blocks of plaintext are identical, then the ciphertext will also be identical
    std::set<bytes> s;
    for (size_t i = 0; i < ciphertext.size(); i += 16)
    {
        s.insert(bytes(ciphertext.begin() + i, ciphertext.begin() + i + 16));
        ++counts;
    }
    // A block was repeated
    if (counts != s.size())
    {
        return ECB;
    }
    return CBC;
}

int main()
{
    EncryptionMode mode;
    std::string s(44, 'A');
    bytes plaintext(s.begin(), s.end());
    int failures = 0;
    const int RUNS = 1000;
    for (int i = 0; i < RUNS; i++)
    {
        auto encrypted = random_encrypter(plaintext, mode);
        auto guessed = oracle(encrypted);
        std::cout << ((mode == ECB) ? "ECB" : "CBC") << " " << ((guessed == ECB) ? "ECB" : "CBC")
                  << " " << hex::from_bytes(encrypted) << std::endl;
        if (guessed != mode)
        {
            failures++;
        }
    }
    std::cout << "Detection mismatch: " << failures << std::endl;
    std::cout << "Total times run: " << RUNS << std::endl;
    std::cout << "Sucess rate: " << std::fixed << std::setprecision(2)
              << static_cast<double>(RUNS - failures) / (RUNS) * 100.0 << " %" << std::endl;
}