#include "crypto.hpp"
#include <fstream>
#include <iostream>
#include <set>
#include <string.h>
#include <string>

const std::string default_filename = "challenge8.txt";

// Check if any of the line is repeated
int main(int argc, char *argv[])
{
    std::string filename = default_filename;
    if (argc == 2)
    {
        filename = argv[1];
    }
    std::ifstream ifs(filename);
    if (!ifs)
    {
        std::cerr << "Could not open input file" << std::endl;
        return 1;
    }
    std::string line;

    while (std::getline(ifs, line))
    {
        size_t counts = 0;
        // If two blocks of plaintext are same, then the ciphertext will also be same
        // Take 32, since 16 bytes = 32 hex characters
        std::set<std::string> s;
        for (size_t i = 0; i < line.size(); i += 32)
        {
            s.insert(line.substr(i, 32));
            ++counts;
        }
        if (counts != s.size())
        {
            std::cout << "Detected AES-ECB" << std::endl;
            std::cout << line << std::endl;
        }
    }
}