#include "crypto.hpp"
#include "gtest/gtest.h"
#include <assert.h>
#include <iostream>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <string>

std::string challenge_ciphertext =
    "091230aade3eb330dbaa4358f88d2a6cd5cf8355cb6823397ad43906df4344557fc4837693c1a8ee3b40acb2323fad"
    "396f4ef50cbf02f853d84873973e430c3053c02a6f8db2ed2708131056df66965b876d513fca5e956810a336e386bc"
    "767d598bede75b91fe5925659d0e6ea0f951a0b5aeea59c0210ae292167fa250e294f23e3ca23ed297839e05350bdb"
    "5481dea2d506da41c4bc7192ff0d93b78138db113055f8b6f49df2a743bf4dc2fb6a845921c263315e2ac58feebd92"
    "c6b23a35fc8ca1b50a77bd8d274b32631a068b617a6f467f13680704b47ddca997a7068a31047dccc4d8c3fd355fdc"
    "d6acb445869ea786a7ed03f5b431ff72f4fb14dffa4d958c10eb57d1cf5cd10b4603cdd0c94da3bf69da01305a37d3"
    "6f1d8a6c5ea1b60b1b1a008c67afe20ac872dd1f3f69bc6497c78afd57c219f03a6d0424aacf756e0b13d118315d25"
    "b38e3be1e1e5d34a5f316283030866b6a2937f6fa43631d7ef5bbac4be9e66c0939f4050ed92fe0ce5c1443b7b2399"
    "4f4c45e4670a9bda946ddaae4d170b9f3dae6fb8da30b8fe815651dc2f9331a449ea1a6c025d1090a27e1bed1a8b18"
    "82f4030115283534003b5f826e7c1d2a703f59b439f52f4c53ad5029c612ba4fa32b99c0303a2dd9d3e6bf16487aa6"
    "c1e9ac75207d1c755c7ba81fd9d85949fd4f76ef11a60bf454170a1740346a2f4e4bdb6c04885f391cac765d1541d0"
    "5ee47a09705ff925e2081ae6b93762b67b55b2273e9c54ce011a138f810e812a6effeb60cb9a78eb8122455c866cd7"
    "c25a4f391c1b374fd150bf3dc7038928241064cf01d58b183aa78bdc71b129fa45a3b92602b5d244a4474e85ee0600"
    "ead3b292fe3c5a4b56b53dacffb6f6078cbc706343adde44be72705eabf14648d2ff7c55772766bc795bf276c29ab7"
    "75d94b758a70d363636644635ac781c18be5b8551ecebb6f16ff2064257b263e1302eebf9794c12df096326419c59e"
    "16196ac4d5d0e8d0d3cd1365052d16e0290d88304c7a009c3a53ca0b664b1b0d9e8e0af6bada0d7e646d7a1afedcb0"
    "212cc5632f23d2450ff30e11e35eef8a9ade1e9664e6a8b80052c9223a22d8a6bd3323b3dbe31b0491cc51157f6b2b"
    "2e5657b361275951ec12b26a53bde235882f89099a1e06a141213bebc308db56e3d3c481092e9dd57cbe6cf129aad4"
    "1d9d31af87de2f56494c78a7c94b3f294009019480435671fd2e1d363d47b9c859cc30e6fe713f6370de0e184d530a"
    "608267ac2c3c45b6a249fc1467f1c83033afd23050d65278645ffb7ca89ac7a6173106302621d216c438b677bf0b03"
    "ac6110f53035d3cf854ac972ee61be10d55dc71e64b6beac91269f869fb479bafd0d3a587eddab845a68978f3fa587"
    "bd00e9cd924e20c4848ac0297e1dd0bc7a9d6e2c9b65dc84af3fb25e33d794a586f7490ecfa7f1f866ef19c1ea89b6"
    "ff1d47dc0e8b1803b958e31635ee5958e6c89bbd633dd688453798f20e51ed9e08bb9d642015c0cd7d287bed30d3ce"
    "5b54a7d3674894a034e3b0a1248d59a766ebe0206d77d0357ea8245694e0b42202c44d6bbbd7ffd8d17e2eb9e6ebee"
    "8cce286f5f7d099571125b35d1423da487a601043ccffdeb810ddec8bf9f562cb3b543e0ff622fc4e1ef79ec44e28c"
    "07e05a3f6d196164ad266086a6571b1100306e0651aac756f43ae17802865981433877cbf78b252e7de874410a8e92"
    "f24afecbe46079f799fe099546f631382d450358759283460177434209699b8cc8f585b1235361ab968cc56a9e3d00"
    "1031e1e9050c17c6d72ccd231b000d3feaf8c8f74a24db2864ca6e5685012585a70d357ef08bdee998018b81046cf6"
    "cc2d7baa0cca438b85dc2c4d1450f27c56798ee5f007310900eb87ac63642a95d67ee601218e282e7998c47f4f75ef"
    "f5f9dd96162484622029e660fa0cd06498251134937c9c765cd9ce58c81a4f8f43b5a078986d862b040436e04eea69"
    "a8a3572db359646fd569375ba56d72941bf47aa6a614e9b2ad3ca1d403d21a7dfb7289932377e637aff09959e6578f"
    "c56e5bd5c0bb83bc68120863ce17c8ba1557cabdd112b3ecabfb50040c95dfa7a87478d114b0cde05da2429271a19e"
    "dddac2d8357d2522c2961f0ca671c293ce614b9eafc5a2f95083b16b14a6433186146a38129a41a043406fa4549bba"
    "68f1659d23d04138b58712f08b497446bdfcc64afe94753b8b1f0b78956036c41db716e8bc4de2ef3dd9713158eee2"
    "6423d8fd1349ae0cdf71f32fd8376e6b9bacd42d868e8d4a0fffb15066c4a0c4f214bd4897904abe154da1d05a800b"
    "b1f5f1caf765ae71e5da70e67c1ac0c02b2a8a86f6a961a9cdf8957574658c142eee7c108985212f3e9084c5baeee3"
    "39e4976c181b871f3318fa9abd15de8aed2d6c9774816b3e62030bcd7b5021b42e55910d331252641e1ac3994f038b"
    "ebd5f141b22538ba78ce128fd7020c2b4dcd30d149dd2453ef5d1af722be6b16820439d468fbaa2ce434a593cd9206"
    "7523c1b8deec15acc5632456160ee9b386526e15c5c2965eeda353ae93c505481f2ed61e4b4c8e2a1595625d642e47"
    "ab48352c78359d64a68cf63673fa1d66a37e741042e75742b78a22e542a62ad53982366c4524dc4e57e119477a0d8e"
    "13a770998478d0447e256618346c5fe8a0f4f12232ca2b8af4fb2474972463a88604636ec724c8590d7143c41410d5"
    "491422102f5da703581da96f7632792423b7c8ff5926d063a4f374babc4ab7998ae316717990938107df1bbc6cfb07"
    "95cbd123e07783129e2e7c2b549a952e47f79b67121a75908522c66e702d8103c0eb3eeede019b06646d3f42a70075"
    "922bbabaa273286131fe6f98858c289546acd4055cd144a8c02f8adc2f69d8795e847373e59dba11cc9c192230fa8b"
    "b58275cc4446be1654e8ce057e1f861294895be59a572ef029088929d910d1d90a9238d72a6856a55aac7a6a87668f"
    "fcf4badb8c9fc71d8ddc2d9c8bb548b87dc371261c6935c42a1cff3d12c95e44605655b19fb42e6892730efa41a059"
    "dda11bb5f970acba9fc0b642e276c4973054e8ff629aef7f7e060603b91b75984f44cae63208ca313bfdbbb27d5058"
    "c31dd63b5cbfc65ee3631a338cbf3e100ca7645f0a855900b512d8aed7ace2e5decf4b0c539d4ab7c3f0678c72205b"
    "7cb1a85c3befe4eaaad12fcebe37480fde1431c69da6748db22b2dfe4709255d30b5119f00b1b6f94298cc48ffd933"
    "a237be54951bc0e578307ea6a33af988217c9b6dd871a639d2074e17de263cd9335261398b2c0cd9957daf995f4829"
    "1462999d92a73369bcb29e07c943848c86cc65dd8b29d08c530d7158d9966587b07ede22d00a5a60b03647ae01f170"
    "8abe134c6ae01b5a4c8deed703b90c4fcdb57186cb4a23c0c2d942d309bbec5d136bb8dd32b2e330edbdfb5f79f021"
    "3358f77375fa8ace57c1cec6dad3e752ea6716fd84c7681e1b0f25de72164193fdf97d483ee2078c8fa3c14ea2cd35"
    "65c15fdddd142edf37275af8bb7d715267961222ffad5faf42b3c4e79734a81e3ca382dd1cfe7d6c3b066e7c165613"
    "81180deb7c855922a5e2c31fce285a42ad11f0d31020e8f3b8c97721ee68cd26becbd838cf9d9145cebd9789f8ab37"
    "f4684ad5fc111eec5af34725a1e0f9038f9c32e4409a45b7ceeeb6ecd441e5b2116f5df1a52dd11f3f690aa53f54df"
    "634a67887e1abf729aa67a8ac6f529f368bf5af0d0a4aa60d3fe132582c8b449dc470e61dbd5c156febc88b2cf19d1"
    "76e801def37368d9631c6e72a442506932e984842794fd36c5c06930d24debd6e28d5b6701237f4cb579a1c62fb675"
    "8f4c12aedcec8e91c7e531a1c21148073d6d1f9867e57788bd4eedf9ceb2af4c3cdfc64257efe289ef677f57e92c34"
    "a5afc27ff0bcc399b1ad8410e7dd0a2766a2a974dbb212e57bd21f29d0b6f166c341d393d517b7c1dd54d4ea71dcbf"
    "8d41665e95cd3f65af9fc3eb5360e19242335a143947177fbe7336410afd0b16b627d197115de418389957dd3e3c20"
    "d254663856017ccbb19e748d61";


TEST(AES_CBC, EncryptionAndDecryption)
{
    std::string plaintext_s = "HERE IS AN EXAMPLE STRING";
    auto plaintext = bytes(plaintext_s.begin(), plaintext_s.end());
    bytes key = {'Y', 'E', 'L', 'L', 'O', 'W', ' ', 'S', 'U', 'B', 'M', 'A', 'R', 'I', 'N', 'E'};
    bytes iv(16, 0);
    auto ciphertext = aes128_encrypt_cbc(plaintext, key, iv);
    auto decrypted = aes128_decrypt_cbc(ciphertext, key, iv);
    ASSERT_EQ(plaintext, decrypted);

    // Empty string
    plaintext_s = "";
    plaintext = bytes(plaintext_s.begin(), plaintext_s.end());
    key = {'Y', 'E', 'L', 'L', 'O', 'W', ' ', 'S', 'U', 'B', 'M', 'A', 'R', 'I', 'N', 'E'};
    iv = bytes(16, 0);
    ciphertext = aes128_encrypt_cbc(plaintext, key, iv);
    decrypted = aes128_decrypt_cbc(ciphertext, key, iv);
    ASSERT_EQ(plaintext, decrypted);

    // Single character
    plaintext_s = "S";
    plaintext = bytes(plaintext_s.begin(), plaintext_s.end());
    key = {'Y', 'E', 'L', 'L', 'O', 'W', ' ', 'S', 'U', 'B', 'M', 'A', 'R', 'I', 'N', 'E'};
    iv = bytes(16, 0);
    ciphertext = aes128_encrypt_cbc(plaintext, key, iv);
    decrypted = aes128_decrypt_cbc(ciphertext, key, iv);
    ASSERT_EQ(plaintext, decrypted);

    // Multiple characters
    plaintext_s = "THE QUICK";
    plaintext = bytes(plaintext_s.begin(), plaintext_s.end());
    key = {'Y', 'E', 'L', 'L', 'O', 'W', ' ', 'S', 'U', 'B', 'M', 'A', 'R', 'I', 'N', 'E'};
    iv = bytes(16, 0);
    ciphertext = aes128_encrypt_cbc(plaintext, key, iv);
    decrypted = aes128_decrypt_cbc(ciphertext, key, iv);
    ASSERT_EQ(plaintext, decrypted);

    plaintext_s = "0123456789abcdef";
    plaintext = bytes(plaintext_s.begin(), plaintext_s.end());
    key = {'Y', 'E', 'L', 'L', 'O', 'W', ' ', 'S', 'U', 'B', 'M', 'A', 'R', 'I', 'N', 'E'};
    iv = bytes(16, 0);
    ciphertext = aes128_encrypt_cbc(plaintext, key, iv);
    decrypted = aes128_decrypt_cbc(ciphertext, key, iv);
    ASSERT_EQ(plaintext, decrypted);

    plaintext_s = "0123456789abcdef0123456789abcdef";
    plaintext = bytes(plaintext_s.begin(), plaintext_s.end());
    key = {'B', 'L', 'U', 'E', 'O', 'W', ' ', 'S', 'U', 'B', 'M', 'A', 'R', 'I', 'N', 'E'};
    iv = bytes(16, 2);
    ciphertext = aes128_encrypt_cbc(plaintext, key, iv);
    decrypted = aes128_decrypt_cbc(ciphertext, key, iv);

    // Long string
    plaintext_s = "The quick brown fox jumps over the lazy dogs the quick brown fox jumps over the "
                  "lazy dogs the quick brown fox jumps over the lazy dogs";
    plaintext = bytes(plaintext_s.begin(), plaintext_s.end());
    key = {'B', 'L', 'U', 'E', 'O', 'W', ' ', 'S', 'U', 'B', 'M', 'A', 'R', 'I', 'N', 'E'};
    iv = bytes(16, 2);
    ciphertext = aes128_encrypt_cbc(plaintext, key, iv);
    decrypted = aes128_decrypt_cbc(ciphertext, key, iv);
    ASSERT_EQ(plaintext, decrypted);
    ASSERT_EQ(plaintext, decrypted);
}

int main(int argc, char *argv[])
{
    // std::string line;
    // std::cout << "Enter plaintext: ";
    // std::getline(std::cin, line);
    // std::string plaintext_s = line;
    // auto plaintext = bytes(plaintext_s.begin(), plaintext_s.end());
    // bytes key = {'Y', 'E', 'L', 'L', 'O', 'W', ' ', 'S', 'U', 'B', 'M', 'A', 'R', 'I', 'N', 'E'};
    // bytes iv(16, 0);
    // auto ciphertext = aes128_encrypt_cbc(plaintext, key, iv);
    // std::cout << hex::from_bytes(ciphertext) << std::endl;
    // auto plain = aes128_decrypt_cbc(ciphertext, key, iv);
    // std::cout << plain << std::endl;

    // std::cout << aes128_decrypt_cbc(hex::to_bytes(challenge_ciphertext), key, iv);

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}