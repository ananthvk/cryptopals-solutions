#pragma once
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

// Note: Don't use it directly with raw string literals (const char*) since the terminating null character is also considered
template <typename T> bytes to_bytes(const T &t) { return to_bytes(std::begin(t), std::end(t)); }

} // namespace hex

namespace base64
{
}