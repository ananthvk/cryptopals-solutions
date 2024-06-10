#include "crypto.hpp"
#include "gtest/gtest.h"
#include <algorithm>
#include <math.h>

// Contains the requency distribution for letters in english,
// characters with lower index are more frequent
static std::string frequency_dist = " etaoinshrdlcumwfgypbvkjxqz";

static int score_table[256] = {0};

const int MIN_KEY_LENGTH = 5;
const int MAX_KEY_LENGTH = 40;
const int NUMBER_OF_KEYS = 10;

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

template <typename Iter1, typename Iter2>
int find_hamming(Iter1 b1_beg, Iter1 b1_end, Iter2 b2_beg, Iter2 b2_end)
{
    // To find the hamming distance, or the number of differing bits, perform XOR between two
    // corresponding bytes The number of ones in the result is the number of differing bits.
    // Use __popcount / bitset to find the number of ones in the byte
    int hamming = 0;
    while (b1_beg != b1_end && b2_beg != b2_end)
    {
        hamming += __builtin_popcount(static_cast<byte>((*b1_beg++) ^ (*b2_beg++)));
    }

    // The byte sequences are of uneven length
    if (b1_beg != b1_end && b2_beg != b2_end)
    {
        throw std::logic_error("Cannot calculate hamming distance for sequences of uneven length");
    }
    return hamming;
}

// Returns the normalized edit distance
// Here, I have used a simple scheme in which the edit distance of first two blocks of key size
// length are considered The normalized edit distance is calculated by dividing the edit distance by
// the key size
double get_normalized_edit_distance(const bytes &ciphertext, int key_size)
{
    // Ciphertext size is smaller than twice the size of key
    if (ciphertext.size() < (2 * key_size))
    {
        return std::numeric_limits<double>::max();
    }
    if (ciphertext.size() >= (4 * key_size))
    {
        // Try averaging 4 key blocks
        double hamming1 =
            find_hamming(ciphertext.begin(), ciphertext.begin() + key_size,
                         ciphertext.begin() + key_size, ciphertext.begin() + 2 * key_size) /
            static_cast<double>(key_size);
        double hamming2 =
            find_hamming(ciphertext.begin() + 2 * key_size, ciphertext.begin() + 3 * key_size,
                         ciphertext.begin() + 3 * key_size, ciphertext.begin() + 4 * key_size) /
            static_cast<double>(key_size);
        return (hamming1 + hamming2) / 2.0;
    }
    else
    {
        double hamming =
            find_hamming(ciphertext.begin(), ciphertext.begin() + key_size,
                         ciphertext.begin() + key_size, ciphertext.begin() + 2 * key_size);
        return hamming / static_cast<double>(key_size);
    }
}

// Uses normalized edit distance to find probable key size
std::vector<int> get_probable_key_size(const bytes &ciphertext, int key_size_min, int key_size_max,
                                       int max_keys)
{
    std::vector<std::pair<double, int>> possible_solutions;

    for (int i = key_size_min; i <= key_size_max; i++)
    {
        auto edit_distance = get_normalized_edit_distance(ciphertext, i);
        possible_solutions.push_back(std::make_pair(edit_distance, i));
    }
    std::sort(possible_solutions.begin(), possible_solutions.end());
    std::vector<int> solution;
    for (const auto &p : possible_solutions)
    {
        if (max_keys > 0)
        {
            solution.push_back(p.second);
            max_keys--;
        }
        else
        {
            break;
        }
    }
    return solution;
}

byte find_key(const bytes &ciphertext)
{
    int max_score = 0;
    bytes english_plaintext;
    byte key = 0;

    // Brute force, check all the bytes and print the one with the highest english score
    for (int i = 0; i < 256; i++)
    {
        auto plaintext = single_byte_XOR(ciphertext, static_cast<byte>(i));
        int score = calculate_score(plaintext);
        if (score > max_score)
        {
            max_score = score;
            english_plaintext = plaintext;
            key = static_cast<byte>(i);
        }
    }
    return key;
}

bytes find_repeated_XOR_key(const bytes &ciphertext)
{
    bytes key;
    auto key_sizes = get_probable_key_size(ciphertext, MIN_KEY_LENGTH, MAX_KEY_LENGTH, NUMBER_OF_KEYS);
    for (const auto &key_size : key_sizes)
    {
        key.clear();
        std::vector<bytes> blocks(key_size);
        for (int i = 0; i < ciphertext.size(); i++)
        {
            blocks[i % key_size].push_back(ciphertext[i]);
        }
        for (const auto &block : blocks)
        {
            key.push_back(find_key(block));
        }
        std::cout << "[" << key_size << "] " << key << std::endl;
    }
    return bytes();
}

TEST(Challenge6, hamming_distance)
{
    std::string s;
    s = "this is a test";
    bytes b1 = bytes(s.begin(), s.end());
    s = "wokka wokka!!!";
    bytes b2 = bytes(s.begin(), s.end());
    ASSERT_EQ(find_hamming(b1.begin(), b1.end(), b2.begin(), b2.end()), 37);

    s = "same string here";
    b1 = bytes(s.begin(), s.end());
    b2 = bytes(s.begin(), s.end());
    ASSERT_EQ(find_hamming(b1.begin(), b1.end(), b2.begin(), b2.end()), 0);
}

TEST(Challenge6, solution)
{
    // Converted the base64 input to hex using python
    std::string ciphertext_s =
        "1d421f4d0b0f021f4f134e3c1a69651f491c0e4e13010b074e1b01164536001e01496420541d1d4333534e6552"
        "060047541c0d454d07040c53123c0c1e08491a09114f144c211a472b00051d4759110409006426075300371606"
        "0c1a17411d015254305f0020130a05474f124808454e653e160938450605081a46074f1f59787e6a62360c1d0f"
        "410d4806551a1b001d4274041e01491a091102527a7f4900483a001a13491a4f45480f1d0d53043a015219010b"
        "411306004c315f53621506070907540b17411416497933350b1b01050f46074f1d4e784e48275204070c455848"
        "0841004f205408740b1d194902000e165c00523069651f4902025400010b074e021053012610154d0207021f4f"
        "1b4e78306936520a010954060709534e021053083b100605490f0f104f3b003a5f472b1c4964334f540210531a"
        "4f051611740c064d0f020e0343524c3d4e002f0b490d084e170d15541d4f0e1c455e280b4d190112070a555378"
        "4e4f6206010b47531d0c0000170a051f0c3a425e4d2e0141220e1c493456416235064f472a7e3b084f011b0153"
        "423704071e0c4e151c0e06072b1a542a17491906595421455707030553073145782c070a411d095259374f0026"
        "1d07491300130113454e0e491704390b5e4d1d06041a4f78773043003b1d1c4e1454151a0c4e494f0807453900"
        "52673a0141130a0600375c4662550a0f125311482c000d000707173b095219010b41071b13473d1a2a161a0c1c"
        "020707480b4f4e0b0000163d0b554d08020d1b181744783069651f490709001911454f190149030d3516174d63"
        "3a09114f15492a56492701491d06000d4811480b16491f0a220052000c4e001a0b5254305b54621b1a4e084b54"
        "62244e0a4f205306350b5209080002114f10452c4e4530521d06064e54090b594e040017453a42521d050f1854"
        "6578732c5b4727525b4e4a0d543100414e1b0116453b0b174d100f465418134e365b002e1b1a1a024e541c0a00"
        "64261d5416740a140b490318540717413c1a532d52050b1300000000000c0a08074524091314491a0906000747"
        "301a2a111d49274743150645461b0102530c2045071d490f0f104f1f41335f002b06491d08551a0c454701000d"
        "536f654840405a4e381b4f5f0d78714e2d11024e084e541b0a4d0b4f1e1c0a3045782b061c4113001d44785655"
        "2119454e2e0018010e454e021053173c1c1f081a4e00001d1d433155553152633d1250111a0641020e0f010433"
        "0c1e041a1a08170a0a50315b4c2b16060d0e4f011b452a27480453043a45170b0f0b02004f134e3c1a542a131d"
        "4e1e4f01480641004f0b1611746f3b4d0a0f0f541b134b3d1a416214051747471d1a09000f010d5308350e174d"
        "010b1354181754761a2a483b4e03474c1d0300003d0e04000a3a455f40493d00191c1d4e784e4f62360c020e4c"
        "1500452a3a070c010073165203064e0511010b49361d0c622b061b4743150645541c1649070a740d13030e4e6b"
        "361a0600215555651e054e0c45111845541c16001d4274111d4d0e0b1554020b002b4e592e1749642856111a45"
        "41000b491c1331175e4d191c00171b1b433d1a4d23190c1d4750111a03450d1b49792721115203061a411d0952"
        "59374f073017490f474c1b0903451c4149796f0d0a074a050241130a06003655572a171b0b4b001a074550020e"
        "0a1649740b1d4d1d070c1143524e371a472b00051d472a27070a4e4e4244532a3c451f1449290e104352483757"
        "45201d0d174b000d0710001e1d06110436090b4d0c0f1554652150395d4827061d0747571d1c0d000f4f1a030a"
        "3b0b534d2a010c114f1d4e785b4e26521a0f1e001d1c440064653f3a357a45240c07070d180e52693b5f003b17"
        "194247591118490027480453063b081b034e4e09151d160034534b2752084e15481d060a00642607070a2c0c11"
        "0c1d070f134f014f78434f37521a1a0647130d17000206021645354505040701417e3c1d00284f4e2901491d13"
        "4f044811521706071445350b164d0e0713184f0154374a00210010070907546233410006051f04742c11084907"
        "12541c174c34534e6552080003000d0710001e0a0603093145131f0c4e0301161b4e7f1a2a6531081b1445541f"
        "0d594e1b0116453217170c021d41151d1700325543291b0749474c1d0300002d1d08091c74221e180c4e6b3900"
        "0449361d00231c0d4e00521b07134900484907172d0c1c0a491a0e541c1b4e3f1a412e1d0709472a350409001a"
        "071b1c10330d5219010b41130717542c55002500060111491a4f455406061a530d3117174d1a010f134f786e37"
        "4d003b1d1c49154554090841140a0d53072d4506050c4e373d3f5250374953275c49646d73000d155007014e53"
        "163b451a0c1b0a4118061945785b0005171b03064e5426045a074f632011351706010c0a4116165254305f0020"
        "131a0b14001c01115407014e5302260a07030d4e6b200717523d1d53621c064e13521d1815490048491c0b7408"
        "1b030c42413d481f00324f5336520e0b13541d0642000a001e1d455e36020c1b0500190e06493b16000b55044e"
        "0f411a0f0c4e494f1d1a023c115201000504540e5246395441361b0a4e6d791b1d45541c0e19030030451f0849"
        "010f170a5241365e000b521d060855130011001a070807455e3c1d1849030813070600305b562752001a472a27"
        "0745531a0a1953013b121c4d0800055403174e3c1a4d275210011252540d04524e654e4b5c740c1c4d04174100"
        "061f45791a792d07454e401944480c534e0210531c3104004349646b2d0007072a5f0035170805024e1d064200"
        "080e1a0749743c3d4c490f0f104f3b003b5b4e62060c020b001d1c452a37001c0145360a16144e1d41130a0654"
        "315407621a061a4b00070749001d00493a4537041c4d1a0304180352492c1a2a111d490a084e531c45420b4f04"
        "120174041c09490a0e1a4806003a5f0031130d4e6d07370910530b4f1d1b0074090b1f000d12540d174c375447"
        "6206064e2e6331444579011a4910043a45110c050241190a5264395e00482b061b4052114815491a0c011a0b73"
        "45134d0f0715584f014f7849542702490c06431f48044e0a4f0c1d012117174d632204004f06483d1a572b060a"
        "0647441b0b114f1c43493a0631495209064e151c0a524439544327521d014743011a0000643c0653063b08174d"
        "1c1e4117031d533d1a412c16490a084e531c45420b4f1a02103517174d63370e014f05413654416210081a134c"
        "114808454e424453243a1c0604040b4d540e1c592f5245301749646d791b1d455406001c140d20450605081a41"
        "3d4f05412b1a572713024247621b11490017001c541731451608080a41031d1d4e3f1a2a111d490d084d11480a"
        "4e424f0c0500261c10020d1741150116002b534e25521d060e53541b0a4e094f637936351c5240444e31180e0b"
        "002c524136520f1b094b0d4808551d060a5336351c5e4d0e014103071b543d1a422d0b454e004f541f0d491a0a"
        "49110a2d451502496411180e0b002c524136520f1b094b0d4808551d060a53223b450505001a04540d1d59741a"
        "472d521e060e541148074f174349140a746f3e0c104e051b181c003954446210060100491148044e0a4f191f04"
        "2d450605081a41121a1c4b211a4d3701000d47541d04090017001c53013d005c4d636431180e0b002c52413652"
        "0f1b094b0d4808551d060a53263b08174d06004d542c1d4d3d1a4f2c5e4902025454050000060a0801455e351e"
        "0c104e151c0e06003e4f4e290b490312531d0b455706061d1645360a0b4d100114541c13597853546e521a0f1e"
        "001d1c452a3e03080a45200d13194908141a040b00354f532b11492f474c1d1c114c0b4f051c103000004d0701"
        "165465224c394300361a081a474601060e594e021c000c3749521a010715114f104f211a632d1f0c4e084e5848"
        "264f030a491c0b78453102040b411b01522a0856413b521d060654540e104e0516491e10270c114d63";
    bytes key = find_repeated_XOR_key(hex::to_bytes(ciphertext_s.begin(), ciphertext_s.end()));
    // [29] Terminator X: Bring the noise
    // is the solution
}

int main(int argc, char *argv[])
{
    build_score_table();
    if (argc >= 2)
    {
        if (strcmp(argv[1], "crack") == 0)
        {
            std::string ciphertext;
            std::cout << "Enter ciphertext(hex encoded): ";
            std::getline(std::cin, ciphertext);
            
            std::cout << ciphertext << std::endl;

            std::cout << "Possible keys: " << std::endl;

            bytes key = find_repeated_XOR_key(hex::to_bytes(ciphertext.begin(), ciphertext.end()));
            return 0;
        }
    }
    // To ecrypt custom strings, here is a small python snippet
    // message = b'Never forget what you are, for surely the world will not.'
    // key = '@'
    // cipher = bytes([i ^ ord(key) for i in message]).hex()
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}