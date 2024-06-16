#include "crypto.hpp"
#include "gtest/gtest.h"
#include <assert.h>
#include <iostream>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <string>

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

bytes aes128_encrypt_cbc(const bytes &unpadded_plaintext, const bytes &key, const bytes &iv)
{
    if (key.size() != 16)
    {
        throw std::logic_error("AES-128 Requires a key size of 16 bytes");
    }
    if (iv.size() != 16)
    {
        throw std::logic_error("AES-128 Requires an iv size of 16 bytes");
    }

    // Pad the plaintext to make its size a multiple of 16
    bytes plaintext = pad_pkcs7(unpadded_plaintext, 16);
    bytes current_iv = iv;

    bytes ciphertext_full;

    // https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
    EVP_CIPHER_CTX *ctx;
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, &key[0], NULL))
    {
        handleErrors();
    }

    // Do not ask openssl to pad the input, since we are doing it manually
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    unsigned char ciphertext[17] = {0};
    int len;

    for (int offset = 0; offset < plaintext.size(); offset += 16)
    {
        // XOR the block with the previous ciphertext / iv if it is the first block

        for (int i = 0; i < 16; i++)
            plaintext[offset + i] = plaintext[offset + i] ^ current_iv[i];

        if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, &plaintext[0] + offset, 16))
        {
            handleErrors();
        }
        ciphertext_full.insert(ciphertext_full.end(), std::begin(ciphertext),
                               std::begin(ciphertext) + len);
        assert(len == 16);
        current_iv = bytes(std::begin(ciphertext), std::begin(ciphertext) + len);
    }

    if (1 != EVP_EncryptFinal(ctx, ciphertext, &len))
        handleErrors();

    ciphertext_full.insert(ciphertext_full.end(), std::begin(ciphertext),
                           std::begin(ciphertext) + len);

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_full;
}

bytes aes128_decrypt_cbc(const bytes &ciphertext, const bytes &key, const bytes &iv)
{
    if (key.size() != 16)
    {
        throw std::logic_error("AES-128 Requires a key size of 16 bytes");
    }
    if (iv.size() != 16)
    {
        throw std::logic_error("AES-128 Requires an iv size of 16 bytes");
    }

    bytes current_iv = iv;
    bytes plaintext_full;
    unsigned char plaintext[17] = {0};
    int len;

    // Using OpenSSL ECB mode to implement CBC
    EVP_CIPHER_CTX *ctx;
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, &key[0], NULL))
    {
        handleErrors();
    }

    // We are handling padding manually
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    for (int offset = 0; offset < ciphertext.size(); offset += 16)
    {

        if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, &ciphertext[0] + offset, 16))
        {
            handleErrors();
        }
        // XOR with previous block of ciphertext / iv to get the final plaintext
        for (int i = 0; i < 16; i++)
            plaintext[i] = plaintext[i] ^ current_iv[i];

        plaintext_full.insert(plaintext_full.end(), std::begin(plaintext),
                              std::begin(plaintext) + len);
        assert(len == 16);
        current_iv = bytes(ciphertext.begin() + offset, ciphertext.begin() + offset + len);
    }

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext, &len))
        handleErrors();

    plaintext_full.insert(plaintext_full.end(), std::begin(plaintext), std::begin(plaintext) + len);

    EVP_CIPHER_CTX_free(ctx);
    return unpad_pkcs7(plaintext_full, 16);
}

int main(int argc, char *argv[])
{
    std::string line;
    std::cout << "Enter plaintext: ";
    std::getline(std::cin, line);
    std::string plaintext_s = line;
    auto plaintext = bytes(plaintext_s.begin(), plaintext_s.end());
    bytes key = {'Y', 'E', 'L', 'L', 'O', 'W', ' ', 'S', 'U', 'B', 'M', 'A', 'R', 'I', 'N', 'E'};
    bytes iv(16, 0);
    auto ciphertext = aes128_encrypt_cbc(plaintext, key, iv);
    std::cout << hex::from_bytes(ciphertext) << std::endl;
    auto plain = aes128_decrypt_cbc(ciphertext, key, iv);
    std::cout << plain << std::endl;

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}