#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdlib.h>
#include "AES_128_CBC.h"

#define CHUNK_SIZE 65536

void EncryptData(uint8_t *data, uint32_t size, AES_CTX *ctx) {
	for (uint32_t offset = 0; offset < size; offset += AES_BLOCK_SIZE) {
		AES_Encrypt(ctx, data + offset, data + offset);
	}
}

int main(int argc, const char *argv[]) {
	if (argc != 3) {
		fprintf(stderr, "Usage: %s <input file> <output file>\n", argv[0]);
		return 1;
	}
	
	uint8_t key[AES_KEY_SIZE];
	memset(key, 0x11, 16);
	
	int fin = open(argv[1], O_RDONLY);
	
	if (fin == -1) {
		printf("Failed to open input file!\n");
		return 1;
	}
	
	int fout = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
	
	if (fout == -1) {
		printf("Failed to open output file!\n");
		close(fin);
		return 1;
	}
	
	uint8_t chunk[CHUNK_SIZE];
	AES_CTX ctx;
	AES_EncryptInit(&ctx, key, key);
	
	ssize_t len;
	
	while ((len = read(fin, chunk, CHUNK_SIZE)) > 0) {
		if (len % AES_BLOCK_SIZE != 0) {
			uint8_t padding_size = AES_BLOCK_SIZE - (len % AES_BLOCK_SIZE);
			memset(chunk + len, padding_size, padding_size);
			len += padding_size;
			
		}
		EncryptData(chunk, len, &ctx);
		write(fout, chunk, len);
	}
	
	close(fin);
	close(fout);
    return 0;
}
