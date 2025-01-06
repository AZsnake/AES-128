#include "AES-128_v_0_1.h"
/*
*	File description: This file is for the storage of the functions used in the encryption algorithm.
*/

// Print function for printing 8-bit array for testing.
static void print_8(uint8_t* to_be_printed)
{
	for (int cyc = 0; cyc < 16; cyc++)
	{
		printf("%02x", to_be_printed[cyc]);
	}
	printf("\n");
}
// Special multiplication for the mix calculation.
uint8_t special_multiply_2(uint8_t to_be_multiplied)
{
	uint8_t out = 0;
	if (to_be_multiplied >> 7 == 1)
	{
		out = (to_be_multiplied << 1) ^ 0x1b; //Polynomial multiplication operation and modulo operation.
	}
	else if (to_be_multiplied >> 7 == 0)
	{
		out = to_be_multiplied << 1;
	}
	return out;
}
uint8_t special_multiply_3(uint8_t to_be_multiplied)
{
	return special_multiply_2(to_be_multiplied) ^ to_be_multiplied;
}
// Assemble 16 8-bit array into 4 32-bit array.
uint32_t* convert_8_32(uint8_t* to_be_converted)
{
	uint32_t* out = (uint32_t*)malloc(sizeof(uint32_t) * 4);
	if (out == NULL)
	{
		perror("Memory allocation failed.");
		return NULL;
	}
	for (int cyc = 0;cyc < 4;cyc++)
	{
		out[cyc] = 0;
	}
	for (int cyc = 0; cyc < 16; cyc++)
	{
		int shift = (3 - (cyc % 4)) * 8; // Calculate shift amount for the byte.
		out[cyc / 4] |= (to_be_converted[cyc] << shift);
	}
	if (to_be_converted) 
	{
		free(to_be_converted);
	}
	return out;
}
// Break 4 32-bit array into 16 8-bit array.
uint8_t* convert_32_8(uint32_t* to_be_converted)
{
	uint8_t* out = (uint8_t*)malloc(sizeof(uint8_t) * 16);
	if (out == NULL)
	{
		perror("Memory allocation failed.");
		return NULL;
	}
	for (int cyc = 0;cyc < 16;cyc++)
	{
		out[cyc] = 0;
	}
	for (int cyc = 0; cyc < 16; cyc++)
	{
		int shift = (3 - (cyc % 4)) * 8; // Calculate shift amount for the byte.
		out[cyc] |= (uint8_t)(to_be_converted[cyc / 4] >> shift);
	}
	if (to_be_converted)
	{
		free(to_be_converted);
	}
	return out;
}
// Generate 32-bit seed array. (This part should be inside the HSM area.)
uint32_t* seed_generation(void)
{
	uint32_t* seed_array = (uint32_t*)malloc(sizeof(uint32_t) * 4);
	if (seed_array == NULL)
	{
		perror("Memory allocation failed.");
		return NULL;
	}
	srand((uint8_t)time(NULL));
	for (int cyc = 0;cyc < 4;cyc++)
	{
		seed_array[cyc] = rand() % 4294967296;
	}
	return seed_array;
}
// RotWord function, which rotate the input left by 1 byte. For instance: 0x12345678 ->0x34567812.
uint32_t* RotWord(uint32_t* to_be_rotated)
{
	uint32_t* out = (uint32_t*)malloc(sizeof(uint32_t));
	if (out == NULL)
	{
		perror("Memory allocation failed.");
		return NULL;
	}
	*out = (*to_be_rotated << 8) | (*to_be_rotated >> 24);
	return out;
}
// Break uint8_t into two 'uint4_t' and substitute them using the sub_table.
uint8_t break_compare_sub(uint8_t to_be_broken)
{
	uint8_t seg[2];
	uint8_t temp1 = to_be_broken;
	uint8_t temp2 = to_be_broken;
	uint8_t max = 0, min = 0;
	seg[0] = (temp1 >> 4);
	seg[1] = (temp2 &= 0b00001111);
	return sub_table[seg[0]][seg[1]];
}
// SubWord function, which substitutes the bytes for 32-bit array.
uint32_t* SubWord(uint32_t* to_be_substituted)
{
	uint8_t seg[4], final[4];
	uint32_t* output = (uint32_t*)malloc(sizeof(uint32_t));
	if (output == NULL)
	{
		perror("Memory allocation failed.");
		return NULL;
	}
	*output = 0; // Must initialize this output, or the |= will generate random numbers.
	for (int cyc = 0;cyc < 4;cyc++)
	{
		uint32_t temp = *to_be_substituted;
		seg[cyc] = (uint8_t)(temp >> (3 - cyc) * 8);
	}
	//free(to_be_substituted);
	for (int cyc = 0;cyc < 4;cyc++)
	{
		final[cyc] = break_compare_sub(seg[cyc]);
	}
	for (int cyc = 0;cyc < 4;cyc++)
	{
		*output |= (final[cyc] << ((3 - cyc) * 8));
	}
	return output;
}
// Rcon function.
uint32_t RoundConstant(int number)
{
	switch (number)
	{
		case 0:
			return 0x01000000;
			break;
		case 1:
			return 0x02000000;
			break;
		case 2:
			return 0x04000000;
			break;
		case 3:
			return 0x08000000;
			break;
		case 4:
			return 0x10000000;
			break;
		case 5:
			return 0x20000000;
			break;
		case 6:
			return 0x40000000;
			break;
		case 7:
			return 0x80000000;
			break;
		case 8:
			return 0x1B000000;
			break;
		case 9:
			return 0x36000000;
			break;
		default:
			perror("Rcon error.");
			return NULL;
	}
}
// Perform calculation for the calculation key 0-44.
uint32_t* expand_calculation_key_44(uint8_t* original_key)
{
	// Initialize the dynamic array and put the previous calculation key into the array.
	uint32_t* W = (uint32_t*)malloc(sizeof(uint32_t) * 44);
	uint32_t* calculation_key_first;
	if (W == NULL)
	{
		perror("Memory allocation failed.");
		return NULL;
	}
	calculation_key_first = convert_8_32(original_key);
	for (int cyc = 0; cyc < 4; cyc++)
	{
		W[cyc] = calculation_key_first[cyc];
	}
	if (calculation_key_first)
	{
		free(calculation_key_first);
	}
	for (int cyc = 4; cyc < 44; cyc++)
	{
		if ((cyc % 4) != 0)
		{
			W[cyc] = W[cyc - 4] ^ W[cyc - 1];
		}
		else if ((cyc % 4) == 0)
		{
			uint32_t* middle = SubWord(RotWord(&W[cyc - 1]));
			W[cyc] = W[cyc - 4] ^ *middle ^ RoundConstant(cyc / 4 - 1);
			free(middle);
		}
	}
	return W;
}
// Perform AddRoundKey operation.
uint8_t* AddRoundKey(uint8_t* to_be_added, uint32_t* key_W, int cyc)
{
	uint32_t* output_32 = (uint32_t*)malloc(sizeof(uint32_t) * 4);
	if (output_32 == NULL)
	{
		perror("Memory allocation failed.");
		return NULL;
	}
	int decrement = 0;
	uint32_t* to_be_added_32 = convert_8_32(to_be_added);
	for (int i=0; i < 4; i++)
	{
		output_32[i] = to_be_added_32[i] ^ key_W[4 * (cyc + i) - decrement];
		decrement += 3; // Decrement by 3 to get the correct key.
	}
	if (to_be_added_32)
	{
		free(to_be_added_32);
	}
	return convert_32_8(output_32);
}
// Perform the SubByte operation.
uint8_t* SubByte(uint8_t* to_be_substituted)
{
	uint8_t* Sb_0_15 = (uint8_t*)malloc(sizeof(uint8_t) * 16);
	if (Sb_0_15 == NULL)
	{
		perror("Memory allocation failed.");
		return NULL;
	}
	for (int cyc = 0;cyc < 16;cyc++)
	{
		Sb_0_15[cyc] = break_compare_sub(to_be_substituted[cyc]);
	}
	if (to_be_substituted)
	{
		free(to_be_substituted);
	}
	return Sb_0_15;
}
// Perform the rot calculation for Sc_0_15. Input should be Sb[0-3].
uint8_t* ShiftRows(uint8_t* to_be_shifted)
{
	uint8_t* Sc_8 = (uint8_t*)malloc(sizeof(uint8_t) * 16);
	if (Sc_8 == NULL)
	{
		perror("Memory allocation failed.");
		return NULL;
	}
	Sc_8[0] = to_be_shifted[0];
	Sc_8[1] = to_be_shifted[5];
	Sc_8[2] = to_be_shifted[10];
	Sc_8[3] = to_be_shifted[15];
	Sc_8[4] = to_be_shifted[4];
	Sc_8[5] = to_be_shifted[9];
	Sc_8[6] = to_be_shifted[14];
	Sc_8[7] = to_be_shifted[3];
	Sc_8[8] = to_be_shifted[8];
	Sc_8[9] = to_be_shifted[13];
	Sc_8[10] = to_be_shifted[2];
	Sc_8[11] = to_be_shifted[7];
	Sc_8[12] = to_be_shifted[12];
	Sc_8[13] = to_be_shifted[1];
	Sc_8[14] = to_be_shifted[6];
	Sc_8[15] = to_be_shifted[11]; // Shift row by brute force.
	if (to_be_shifted)
	{
		free(to_be_shifted);
	}
	return Sc_8;
}
// Perform the mix calculation for Sd_0_15. Input should be Sc[0-15].
uint8_t* MixColumns(uint8_t* to_be_mixed)
{
	uint8_t* Sd_8 = (uint8_t*)malloc(sizeof(uint8_t) * 16);
	if (Sd_8 == NULL)
	{
		perror("Memory allocation failed.");
		return NULL;
	}
	for (int cyc = 0; cyc < 4; cyc++)
	{
		Sd_8[0 + 4 * cyc] = special_multiply_2(to_be_mixed[0 + 4 * cyc]) ^ special_multiply_3(to_be_mixed[1 + 4 * cyc]) ^ to_be_mixed[2 + 4 * cyc] ^ to_be_mixed[3 + 4 * cyc];
		Sd_8[1 + 4 * cyc] = to_be_mixed[0 + 4 * cyc] ^ special_multiply_2(to_be_mixed[1 + 4 * cyc]) ^ special_multiply_3(to_be_mixed[2 + 4 * cyc]) ^ to_be_mixed[3 + 4 * cyc];
		Sd_8[2 + 4 * cyc] = to_be_mixed[0 + 4 * cyc] ^ to_be_mixed[1 + 4 * cyc] ^ special_multiply_2(to_be_mixed[2 + 4 * cyc]) ^ special_multiply_3(to_be_mixed[3 + 4 * cyc]);
		Sd_8[3 + 4 * cyc] = special_multiply_3(to_be_mixed[0 + 4 * cyc]) ^ to_be_mixed[1 + 4 * cyc] ^ to_be_mixed[2 + 4 * cyc] ^ special_multiply_2(to_be_mixed[3 + 4 * cyc]);
	}
	/*
	* The matrix above is: |02 03 01 01|
	*					   |01 02 03 01|
	*                      |01 01 02 03|
	*                      |03 01 01 02|
	*/
	if (to_be_mixed)
	{
		free(to_be_mixed);
	}
	return Sd_8;
}
// Function that gets the final calculation result.
uint32_t* encrypt_AES_128(uint8_t* original_key, uint32_t* to_be_encrypted)
{
	uint32_t* calculation_key;
	calculation_key = expand_calculation_key_44(original_key);
	uint8_t* state;
	// Malloc calculation_key_32, which is a duplicate of the original calculation_key. So during the convert operation, calculation_key won't be freed.
	uint32_t* calculation_key_32 = (uint32_t*)malloc(sizeof(uint32_t) * 44);
	if (calculation_key_32 == NULL)
	{
		perror("Memory allocation failed.");
		return NULL;
	}
	for (int cyc = 0; cyc < 44; cyc++)
	{
		*(calculation_key_32 + cyc) = *(calculation_key + cyc);
	}
	state = AddRoundKey(convert_32_8(calculation_key_32), to_be_encrypted, 0);
	for (int cyc = 1; cyc < 10; cyc++)
	{
		state = SubByte(state);
		state = ShiftRows(state);
		state = MixColumns(state);
		state = AddRoundKey(state, calculation_key, cyc);
	}
	state = SubByte(state);
	state = ShiftRows(state);
	state = AddRoundKey(state, calculation_key, 10);
	uint32_t* state_32 = convert_8_32(state);
	return state_32;
}