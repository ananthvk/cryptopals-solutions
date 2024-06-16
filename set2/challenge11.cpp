#include "crypto.hpp"
#include "gtest/gtest.h"
#include <assert.h>
#include <iostream>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <random>
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


// Sets mode to 0 if ECB was used, 1 for CBC
bytes random_encrypter(const bytes &plaintext, int &mode)
{
    static std::random_device dev;
    static std::mt19937 rng(dev());
    std::uniform_int_distribution<int> dist01(0, 1);

    mode = dist01(rng);

    std::uniform_int_distribution<int> bytes_to_add(5, 10);
    int bytes_before = bytes_to_add(rng);
    int bytes_after = bytes_to_add(rng);
    return bytes();

}

int main()
{
    int mode;
    std::string s = "HELLO";
    bytes plaintext(s.begin(), s.end());
    random_encrypter(plaintext, mode);
}