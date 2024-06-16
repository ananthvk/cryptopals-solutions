#pragma once
#include <assert.h>
#include <iostream>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <ostream>
#include <random>
#include <stdexcept>
#include <stdint.h>
#include <string>
#include <vector>

using byte = uint8_t;
using bytes = std::vector<uint8_t>;

// To convert hex to base64, I am going to use two different functions, hex::to_bytes and
// base64::from_bytes

namespace hex
{
// Converts a sequence of bytes to hexadecimal
const static byte DECODE_TABLE[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

template <typename Iter> inline bytes from_bytes(Iter begin, Iter end)
{
    bytes result;
    for (; begin != end; begin++)
    {
        result.push_back(DECODE_TABLE[(*begin) >> 4]);
        result.push_back(DECODE_TABLE[(*begin) & 0xf]);
    }
    return result;
}

template <typename T> inline bytes from_bytes(const T &t)
{
    return from_bytes(std::begin(t), std::end(t));
}

// This function converts a hex string from [begin, end)
template <typename Iter> inline bytes to_bytes(const Iter begin, const Iter end)
{
    bytes decoded;
    size_t sz = 0;
    byte b = 0;

    // The input string is empty
    if (begin == end)
        return decoded;

    for (auto it = begin; it != end; it++)
    {
        auto ch = static_cast<byte>(tolower(*it));
        if (!isalnum(ch))
        {
            throw std::runtime_error("Invalid character '" + std::string(1, ch) + "' for base-16");
        }

        b <<= 4;
        if (isdigit(ch))
            b |= static_cast<uint8_t>(ch - '0');
        else
            b |= static_cast<uint8_t>(ch - 'a' + 10);

        // At every odd index, i.e. 1, 3, 5 ..., add the byte to decoded vector
        if (sz % 2 != 0)
        {
            decoded.push_back(b);
            b = 0;
        }
        sz++;
    }
    if (sz % 2 != 0)
    {
        // Hex strings should always be of even length
        throw std::runtime_error("Invalid length " + std::to_string(sz) + " for base-16");
    }
    return decoded;
}

// Note: Don't use it directly with raw string literals (const char*) since the terminating null
// character is also considered
template <typename T> inline bytes to_bytes(const T &t)
{
    return to_bytes(std::begin(t), std::end(t));
}

} // namespace hex

namespace base64
{
// [chr(i) for i in list(range(65, 91)) + list(range(97,123)) + list(range(48, 58))] + ['+', '/']
const static byte ENCODE_TABLE[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
                                    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
                                    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
                                    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
                                    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

template <typename Iter> inline bytes from_bytes(Iter begin, Iter end)
{
    bytes encoded;

    if (begin == end)
        return encoded;

    // Read groups of three bytes (24 bits) and convert them to four base64 characters
    // If the last group contains less than three bytes, apply padding
    byte b1, b2, b3;
    while (true)
    {
        b1 = static_cast<byte>(*begin++);
        encoded.push_back(ENCODE_TABLE[(b1 >> 2)]);
        if (begin == end)
        {
            // Only one byte found, this is the last block
            // Get the two LSB of the first byte
            encoded.push_back(ENCODE_TABLE[(b1 & 0x3) << 4]);
            encoded.push_back('=');
            encoded.push_back('=');
            break;
        }

        b2 = static_cast<byte>(*begin++);
        encoded.push_back(ENCODE_TABLE[((b1 & 0x3) << 4) | (b2 >> 4)]);
        if (begin == end)
        {
            // Two bytes found, this is the last block
            encoded.push_back(ENCODE_TABLE[((b2 & 0xf) << 2)]);
            encoded.push_back('=');
            break;
        }

        b3 = static_cast<byte>(*begin++);
        encoded.push_back(ENCODE_TABLE[((b2 & 0xf) << 2) | (b3 >> 6)]);
        encoded.push_back(ENCODE_TABLE[(b3 & 0x3f)]);
        if (begin == end)
        {
            // Three bytes found, this is the last block
            break;
        }
        // There are more blocks
    }
    return encoded;
}

template <typename T> inline bytes from_bytes(const T &t)
{
    return from_bytes(std::begin(t), std::end(t));
}
} // namespace base64

// Convenience function to display bytes, displays non printable characters using the \x notation

inline std::ostream &operator<<(std::ostream &os, const bytes &bytestr)
{
    for (const auto &byt : bytestr)
    {
        if (isprint(byt))
            os << static_cast<char>(byt);
        else
        {
            if (byt == ' ')
            {
                os << " ";
            }
            else if (byt == '\n')
            {
                os << "\\n";
            }
            else if (byt == '\t')
            {
                os << "\\t";
            }
            else if (byt == '\r')
            {
                os << "\\r";
            }
            else
            {
                os << '\\' << 'x' << static_cast<char>(hex::DECODE_TABLE[(byt) >> 4])
                   << static_cast<char>(hex::DECODE_TABLE[(byt) & 0xf]);
            }
        }
    }
    return os;
}

// Pads the input using the PKCS#7 Scheme, the returned bytes has a size which is a mutliple of
// block size.
// Even if the text length is an exact multiple of block size, padding is still applied
inline bytes pad_pkcs7(const bytes &text, int block_size)
{
    if (block_size > 255)
    {
        throw std::logic_error("PKCS#7 Padding block size cannot be greater than 255 bytes");
    }
    bytes padded_text = text;
    int n_padding_chars = block_size - (text.size() % block_size);
    bytes temp(n_padding_chars, static_cast<byte>(n_padding_chars));

    padded_text.insert(padded_text.end(), temp.begin(), temp.end());
    return padded_text;
}

inline bytes unpad_pkcs7(const bytes &text, int block_size)
{
    if (block_size > 255)
    {
        throw std::logic_error("PKCS#7 Padding block size cannot be greater than 255 bytes");
    }
    // Get number of padding bytes
    int padding_bytes = static_cast<int>(text.back());
    if (padding_bytes > text.size())
    {
        throw std::runtime_error("Number of padding bytes > text size");
    }
    return bytes(text.begin(), text.begin() + text.size() - padding_bytes);
}

inline bytes fixed_XOR(bytes &b1, bytes &b2)
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

inline void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

inline bytes aes128_encrypt_cbc(const bytes &unpadded_plaintext, const bytes &key, const bytes &iv)
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

inline bytes aes128_encrypt_ecb(const bytes &unpadded_plaintext, const bytes &key)
{
    if (key.size() != 16)
    {
        throw std::logic_error("AES-128 Requires a key size of 16 bytes");
    }
    // Pad the plaintext to make its size a multiple of 16
    bytes plaintext = pad_pkcs7(unpadded_plaintext, 16);

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
        if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, &plaintext[0] + offset, 16))
        {
            handleErrors();
        }
        ciphertext_full.insert(ciphertext_full.end(), std::begin(ciphertext),
                               std::begin(ciphertext) + len);
        assert(len == 16);
    }

    if (1 != EVP_EncryptFinal(ctx, ciphertext, &len))
        handleErrors();

    ciphertext_full.insert(ciphertext_full.end(), std::begin(ciphertext),
                           std::begin(ciphertext) + len);

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_full;
}

inline bytes aes128_decrypt_cbc(const bytes &ciphertext, const bytes &key, const bytes &iv)
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

inline bytes aes128_decrypt_ecb(const bytes &ciphertext, const bytes &key)
{
    if (key.size() != 16)
    {
        throw std::logic_error("AES-128 Requires a key size of 16 bytes");
    }

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

        plaintext_full.insert(plaintext_full.end(), std::begin(plaintext),
                              std::begin(plaintext) + len);
        assert(len == 16);
    }

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext, &len))
        handleErrors();

    plaintext_full.insert(plaintext_full.end(), std::begin(plaintext), std::begin(plaintext) + len);

    EVP_CIPHER_CTX_free(ctx);
    return unpad_pkcs7(plaintext_full, 16);
}