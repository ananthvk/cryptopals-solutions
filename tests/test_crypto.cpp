#include "gtest/gtest.h"

TEST(ATest, Empty)
{
}

int main(int argc, char *argv[])
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}