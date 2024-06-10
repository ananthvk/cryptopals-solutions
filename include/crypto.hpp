#pragma once
#include <stdexcept>
#include <stdint.h>
#include <string>
#include<ostream>
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

template <typename Iter> bytes from_bytes(Iter begin, Iter end)
{
    bytes result;
    for (; begin != end; begin++)
    {
        result.push_back(DECODE_TABLE[(*begin) >> 4]);
        result.push_back(DECODE_TABLE[(*begin) & 0xf]);
    }
    return result;
}

template <typename T> bytes from_bytes(const T &t)
{
    return from_bytes(std::begin(t), std::end(t));
}

// This function converts a hex string from [begin, end)
template <typename Iter> bytes to_bytes(const Iter begin, const Iter end)
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
template <typename T> bytes to_bytes(const T &t) { return to_bytes(std::begin(t), std::end(t)); }

} // namespace hex

namespace base64
{
// [chr(i) for i in list(range(65, 91)) + list(range(97,123)) + list(range(48, 58))] + ['+', '/']
const static byte ENCODE_TABLE[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
                                    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
                                    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
                                    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
                                    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

template <typename Iter> bytes from_bytes(Iter begin, Iter end)
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

template <typename T> bytes from_bytes(const T &t)
{
    return from_bytes(std::begin(t), std::end(t));
}
} // namespace base64

// Convenience function to display bytes, displays non printable characters using the \x notation

std::ostream &operator<<(std::ostream &os, const bytes &bytestr)
{
    for (const auto &byt : bytestr)
    {
        if (isprint(byt))
            os << static_cast<char>(byt);
        else
        {
            os << '\\' << 'x' 
               << static_cast<char>(hex::DECODE_TABLE[(byt) >> 4])
               << static_cast<char>(hex::DECODE_TABLE[(byt) & 0xf]);
        }
    }
    return os;
}