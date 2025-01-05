// AES-128.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <stdio.h>
#include "AES-128_v_0_1.h"

int main(void)
{
    // Initialize the original key, which is a 128-bit integer or 32 hex numbers in total. It is devided into 15 segments.
    uint32_t* original_key_test = (uint32_t*)malloc(sizeof(uint32_t) * 4);
	if (original_key_test == NULL)
	{
		perror("Memory allocation failed.");
		return 1;
	}
    *(original_key_test) = 0x00010203;
    *(original_key_test + 1) = 0x04050607;
    *(original_key_test + 2) = 0x08090a0b;
    *(original_key_test + 3) = 0x0c0d0e0f;
	uint8_t* original_key_test_8 = convert_32_8(original_key_test);
    uint32_t* plain = (uint32_t*)malloc(sizeof(uint32_t) * 4);
	if (plain == NULL)
	{
		perror("Memory allocation failed.");
		return 1;
	}
    *(plain) = 0x00112233;
    *(plain + 1) = 0x44556677;
    *(plain + 2) = 0x8899aabb;
    *(plain + 3) = 0xccddeeff;
    uint32_t* encryption_result;
	encryption_result = get_encryption_result(original_key_test_8, plain);
    for (int cyc = 0; cyc < 4; cyc++)
    {
        printf("%08x\n", encryption_result[cyc]);
    }
    getchar();
    return 0;
}
