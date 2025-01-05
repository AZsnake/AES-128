#include "AES-128_v_0_1.h"
/*
*	File description: This file is for the storage of the functions used in the encryption algorithm.
*/

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
// Generate seed array. (This part should be inside the HSM area.)
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
	*out = *to_be_rotated;
	uint32_t temp1 = *to_be_rotated;
	uint32_t last = (temp1 >> 24);
	*out <<= 8;
	*out |= last;
	return out;
}
// SubWord function, which substitutes the bytes.
// Break uint8_t into two uint4_ts and substitute them.
uint8_t break_compare_sub(uint8_t to_be_broken)
{
	uint8_t seg[2];
	uint8_t temp1 = to_be_broken;
	uint8_t temp2 = to_be_broken;
	uint8_t max = 0, min = 0;
	seg[0] = (temp1 >> 4);
	seg[1] = (temp2 &= 0b00001111);
	if (seg[0] >= seg[1])
	{
		max = seg[0];
		min = seg[1];
	}
	else if (seg[0] < seg[1])
	{
		max = seg[1];
		min = seg[0];
	}
	//printf("- %x %x %x\n", min, max, sub_table[min][max]);
	return sub_table[min][max];
}
uint32_t* SubWord(uint32_t* to_be_substituted)
{
	uint8_t seg[4], final[4];
	uint32_t* output = (uint32_t*)malloc(sizeof(uint32_t));
	if (output == NULL)
	{
		perror("Memory allocation failed.");
		return NULL;
	}
	*output = 0; // Gotta initialize this output, or the |= will generate random numbers.
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
uint32_t Rcon(int number)
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
// Perform the calculation for the calculation key 0-3.
uint32_t* get_calculation_key_0_3(uint8_t* original_key)
{
	// Initialize W and set its values to 0.
	uint32_t* W;
	W = convert_8_32(original_key);
	return W;
}
// Perform calculation for the calculation key 4-44.
uint32_t* get_calculation_key_0_43(uint8_t* original_key)
{
	// Initialize the dynamic array and put the previous calculation key into the array.
	uint32_t* W = (uint32_t*)malloc(sizeof(uint32_t) * 44);
	uint32_t* calculation_key_first;
	if (W == NULL)
	{
		perror("Memory allocation failed.");
		return NULL;
	}
	calculation_key_first = get_calculation_key_0_3(original_key);
	for (int cyc = 0; cyc < 4; cyc++)
	{
		W[cyc] = *(calculation_key_first + cyc);
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
			W[cyc] = W[cyc - 4] ^ *middle ^ Rcon(cyc / 4 - 1);
			free(middle);
		}
	}
	return W;
}
// Perform calculation XOR to get Sa_0_15. Input should be key_W[0-3].
uint8_t* get_Sa_round_0(uint32_t* key_W, uint32_t* plain)
{
	uint32_t* Sa_32 = (uint32_t*)malloc(sizeof(uint32_t) * 4);
	uint8_t* Sa_8;
	if (Sa_32 == NULL)
	{
		perror("Memory allocation failed.");
		return NULL;
	}
	for (int cyc = 0; cyc < 4; cyc++)
	{
		Sa_32[cyc] = plain[cyc] ^ key_W[cyc];
	}
	Sa_8 = convert_32_8(Sa_32);
	if (plain)
	{
		free(plain);
	}
	return Sa_8;
}
// Perform calculation to further get Sa.
uint8_t* get_Sa_round_n(uint8_t* Sd_0_15, uint32_t* key_W, int cyc)
{
	uint32_t* Sa_32 = (uint32_t*)malloc(sizeof(uint32_t) * 4);
	if (Sa_32 == NULL)
	{
		perror("Memory allocation failed.");
		return NULL;
	}
	uint8_t* Sa_8 = (uint8_t*)malloc(sizeof(uint8_t) * 16);
	if (Sa_8 == NULL)
	{
		perror("Memory allocation failed.");
		return NULL;
	}
	int decrement = 0;
	uint32_t* Sd_32 = convert_8_32(Sd_0_15);
	for (int i=0; i < 4; i++)
	{
		Sa_32[i] = Sd_32[i] ^ key_W[4 * cyc - decrement];
		decrement += 3; // Decrement by 3 to get the correct key.
	}
	if (Sd_32)
	{
		free(Sd_32);
	}
	Sa_8 = convert_32_8(Sa_32);
	return Sa_8;
}
// Perform the sub calculation for Sb_0_15. Input should be Sa[0-15].
uint8_t* get_Sb(uint8_t* Sa_0_15)
{
	uint8_t* Sb_0_15 = (uint8_t*)malloc(sizeof(uint8_t) * 16);
	if (Sb_0_15 == NULL)
	{
		perror("Memory allocation failed.");
		return NULL;
	}
	for (int cyc = 0;cyc < 16;cyc++)
	{
		Sb_0_15[cyc] = break_compare_sub(Sa_0_15[cyc]);
	}
	if (Sa_0_15)
	{
		free(Sa_0_15);
	}
	return Sb_0_15;
}
// Perform the rot calculation for Sc_0_15. Input should be Sb[0-3].
uint8_t* get_Sc(uint8_t* Sb_0_15)
{
	uint8_t* Sc_8 = (uint8_t*)malloc(sizeof(uint8_t) * 16);
	if (Sc_8 == NULL)
	{
		perror("Memory allocation failed.");
		return NULL;
	}
	Sc_8[0] = Sb_0_15[0];
	Sc_8[1] = Sb_0_15[5];
	Sc_8[2] = Sb_0_15[10];
	Sc_8[3] = Sb_0_15[15];
	Sc_8[4] = Sb_0_15[4];
	Sc_8[5] = Sb_0_15[9];
	Sc_8[6] = Sb_0_15[14];
	Sc_8[7] = Sb_0_15[3];
	Sc_8[8] = Sb_0_15[8];
	Sc_8[9] = Sb_0_15[13];
	Sc_8[10] = Sb_0_15[2];
	Sc_8[11] = Sb_0_15[7];
	Sc_8[12] = Sb_0_15[12];
	Sc_8[13] = Sb_0_15[1];
	Sc_8[14] = Sb_0_15[6];
	Sc_8[15] = Sb_0_15[11]; // Shift row by brute force.
	if (Sb_0_15)
	{
		free(Sb_0_15);
	}
	return Sc_8;
}
// Perform the mix calculation for Sd_0_15. Input should be Sc[0-15].
uint8_t* get_Sd(uint8_t* Sc_0_15)
{
	uint8_t* Sd_8 = (uint8_t*)malloc(sizeof(uint8_t) * 16);
	if (Sd_8 == NULL)
	{
		perror("Memory allocation failed.");
		return NULL;
	}
	for (int cyc = 0; cyc < 4; cyc++)
	{
		Sd_8[0 + 4 * cyc] = (2 * Sc_0_15[0 + 4 * cyc]) ^ Sc_0_15[1 + 4 * cyc] ^ Sc_0_15[2 + 4 * cyc] ^ (3 * Sc_0_15[3 + 4 * cyc]);
		Sd_8[1 + 4 * cyc] = Sc_0_15[0 + 4 * cyc] ^ Sc_0_15[1 + 4 * cyc] ^ (3 * Sc_0_15[2 + 4 * cyc]) ^ (2 * Sc_0_15[3 + 4 * cyc]);
		Sd_8[2 + 4 * cyc] = Sc_0_15[0 + 4 * cyc] ^ (3 * Sc_0_15[1 + 4 * cyc]) ^ (2 * Sc_0_15[2 + 4 * cyc]) ^ Sc_0_15[3 + 4 * cyc];
		Sd_8[3 + 4 * cyc] = (3 * Sc_0_15[0 + 4 * cyc]) ^ (2 * Sc_0_15[1 + 4 * cyc]) ^ Sc_0_15[2 + 4 * cyc] ^ Sc_0_15[3 + 4 * cyc];
	}
	if (Sc_0_15)
	{
		free(Sc_0_15);
	}
	return Sd_8;
}
// Perform the mix calculation for CR.
uint8_t* get_CR(uint8_t* Sc_last_8, uint32_t* key_W)
{
	uint32_t* CR_32 = (uint32_t*)malloc(sizeof(uint32_t) * 4);
	if (CR_32 == NULL)
	{
		perror("Memory allocation failed.");
		return NULL;
	}
	uint32_t* Sc_last_32 = (uint32_t*)malloc(sizeof(uint32_t) * 4);
	if (Sc_last_32 == NULL)
	{
		perror("Memory allocation failed.");
		return NULL;
	}
	uint8_t* CR_8 = (uint8_t*)malloc(sizeof(uint8_t) * 16);
	if (CR_8 == NULL)
	{
		perror("Memory allocation failed.");
		return NULL;
	}
	Sc_last_32 = convert_8_32(Sc_last_8);
	for (int cyc = 40; cyc < 44; cyc++)
	{
		CR_32[cyc - 40] = Sc_last_32[cyc - 40] ^ key_W[cyc];
	}
	if (Sc_last_32)
	{
		free(Sc_last_32);
	}
	CR_8 = convert_32_8(CR_32);
	return CR_8;
}
uint32_t* get_encryption_result(uint8_t* original_key, uint32_t* to_be_encrypted)
{
	uint32_t* calculation_key;
	calculation_key = get_calculation_key_0_43(original_key);
	printf("CKeys : \n");
	for (int cyc = 0; cyc < 44; cyc++)
	{
		printf("%08x", calculation_key[cyc]);
		if ((cyc + 1) % 4 == 0)
		{
			printf("\n");
		}
	}
	printf("\n");
	uint8_t* Sa_0 = get_Sa_round_0(calculation_key, to_be_encrypted);
	printf("Sa_0 : ");
	for (int cyc = 0; cyc < 16; cyc++)
	{
		printf("%02x", Sa_0[cyc]);
	}
	printf("\n");
	uint8_t* Sb_0 = get_Sb(Sa_0);
	printf("Sb_0 : ");
	for (int cyc = 0; cyc < 16; cyc++)
	{
		printf("%02x", Sb_0[cyc]);
	}
	printf("\n");
	uint8_t* Sc_0 = get_Sc(Sb_0);
	printf("Sc_0 : ");
	for (int cyc = 0; cyc < 16; cyc++)
	{
		printf("%02x", Sc_0[cyc]);
	}
	printf("\n");
	uint8_t* Sd_0 = get_Sd(Sc_0);
	printf("Sd_0 : ");
	for (int cyc = 0; cyc < 16; cyc++)
	{
		printf("%02x", Sd_0[cyc]);
	}
	printf("\n");
	uint8_t* Sa_n, * Sb_n, * Sc_n, * Sd_n;
	Sd_n = Sd_0;
	for (int cyc = 1;cyc < 10;)
	{
		Sa_n = get_Sa_round_n(Sd_n, calculation_key, cyc);
		printf("Sa_%d : ", cyc);
		for (int cyc = 0; cyc < 16; cyc++)
		{
			printf("%02x", Sa_n[cyc]);
		}
		printf("\n");
		cyc++;
		Sb_n = get_Sb(Sa_n);
		printf("Sb_%d : ", cyc-1);
		for (int cyc = 0; cyc < 16; cyc++)
		{
			printf("%02x", Sb_n[cyc]);
		}
		printf("\n");
		Sc_n = get_Sc(Sb_n);
		printf("Sc_%d : ", cyc-1);
		for (int cyc = 0; cyc < 16; cyc++)
		{
			printf("%02x", Sc_n[cyc]);
		}
		printf("\n");
		if (cyc == 10)
		{
			break;
		}
		Sd_n = get_Sd(Sc_n);
		printf("Sd_%d : ", cyc-1);
		for (int cyc = 0; cyc < 16; cyc++)
		{
			printf("%02x", Sd_n[cyc]);
		}
		printf("\n");
	}
	uint8_t* CR = get_CR(Sc_n, calculation_key);
	printf("CR   : ");
	for (int cyc = 0; cyc < 16; cyc++)
	{
		printf("%02x", CR[cyc]);
	}
	printf("\n");
	uint32_t* out = convert_8_32(CR);
	return out;
}