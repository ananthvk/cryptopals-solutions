#include "crypto.hpp"
#include <iostream>
#include <map>
const int block_size = 16;

std::string unknown_string =
    "526f6c6c696e2720696e206d7920352e300a57697468206d79207261672d746f7020646f776e20736f206d79206861"
    "69722063616e20626c6f770a546865206769726c696573206f6e207374616e64627920776176696e67206a75737420"
    "746f207361792068690a44696420796f752073746f703f204e6f2c2049206a7573742064726f76652062790a";

// A random key
bytes key = {190, 153, 206, 182, 196, 74, 119, 85, 195, 88, 4, 88, 76, 157, 28, 14};

bytes encrypt(const bytes &buffer)
{
    // Encrypts a buffer using a random but consistent key
    return aes128_encrypt_ecb(buffer, key);
}

// Encrypts the buffer after appending an unknown string
bytes oracle(const bytes &buffer)
{
    bytes plaintext = buffer;
    bytes unknown = hex::to_bytes(unknown_string.begin(), unknown_string.end());
    plaintext.insert(plaintext.end(), unknown.begin(), unknown.end());
    return encrypt(plaintext);
}

bytes get_nth_block(const bytes &ciphertext, int n)
{
    return bytes(ciphertext.begin() + (n * block_size),
                 ciphertext.begin() + (n * block_size) + block_size);
}

bytes buildblock(const bytes &last_bytes)
{
    bytes buffer;
    if (last_bytes.size() == block_size)
    {
        buffer = bytes(last_bytes.begin() + 1, last_bytes.end());
        buffer.push_back('A');
    }
    else if (last_bytes.size() == 0)
    {
        buffer = bytes(block_size, 'A');
    }
    else if (last_bytes.size() > block_size)
    {
        buffer = bytes(last_bytes.begin() + (last_bytes.size() - block_size) + 1, last_bytes.end());
        buffer.push_back('A');
    }
    else
    {
        buffer = bytes(block_size, 'A');
        std::copy(last_bytes.begin(), last_bytes.end(),
                  buffer.begin() + (block_size - last_bytes.size() - 1));
    }
    return buffer;
}

// If any bytes have been discovered, add it to the buffer
std::map<bytes, byte> build_dictionary(const bytes &last_bytes)
{
    // Builds a dictionary mapping the output of aes ecb of a string with the last byte being every
    // possible byte Eg: AAAA..AA -> [byte] AAAA..AB -> [byte] AAAA..AC -> [byte] AAAA..Ax -> [byte]
    // AAAA..A* -> [byte]
    // AAAA..A. -> [byte]
    // ...
    std::map<bytes, byte> dictionary;

    // Only consider the first block, since the second block comprises only of padding
    bytes buffer = buildblock(last_bytes);
    // For every possible byte,
    for (int i = 0; i < 255; i++)
    {
        buffer[block_size - 1] = static_cast<byte>(i);
        bytes ciphertext = encrypt(buffer);
        dictionary[get_nth_block(ciphertext, 0)] = static_cast<byte>(i);
    }

    return dictionary;
}

int main()
{
    // Detect the blocksize of the cipher
    // for (int i = 0; i < 20; i++)
    //{
    //    bytes inp(i, 'A');
    //    auto ciphertext = oracle(inp);
    //    std::cout << hex::from_bytes(ciphertext) << std::endl;
    //}
    // After a few iterations, the first block 0ed3c5d9eb279a6625bf95706c609d55 remains unchanged,
    // so the blocksize used is 16 bytes

    // Determine the number of blocks by calling the oracle with no bytes
    int nbytes = oracle(bytes()).size();
    int nblocks = nbytes / block_size;

    bytes decoded;
    for (int j = 0; j < nblocks; j++)
    {
        bytes b(block_size - 1, 'A');
        for (int i = 0; i < 16; i++)
        {
            auto dict = build_dictionary(decoded);
            auto ciphertext = oracle(b);
            auto it = dict.find(get_nth_block(ciphertext, j));
            if (it != dict.end())
            {
                decoded.push_back(it->second);
            }
            else
            {
                std::cout << decoded << std::endl;
                std::cout << "NOT FOUND";
                return 1;
            }
            if (!b.empty())
                b.pop_back();
        }
    }
    std::cout << decoded << std::endl;
}