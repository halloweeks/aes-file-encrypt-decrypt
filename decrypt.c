#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "AES_128_CBC.h"

#define CHUNK_SIZE 65536

void DecryptData(uint8_t *data, uint32_t size, AES_CTX *ctx) {
    for (uint32_t offset = 0; offset < size; offset += 16) {
        AES_Decrypt(ctx, data + offset, data + offset);
    }
}

int main(int argc, const char *argv[]) {
	if (argc != 3) {
		printf("Usage: %s <input file> <output file>\n", argv[0]);
		return 1;
	}
	
	uint8_t key[AES_KEY_SIZE];
	memset(key, 0x11, AES_KEY_SIZE);
	
	int fin = open(argv[1], O_RDONLY);
	
	if (fin == -1) {
		perror("Failed to open input file");
		return 1;
	}
	
	off_t file_size = lseek(fin, 0, SEEK_END);
	
	if (file_size == -1) {
		perror("Failed to get file size");
		close(fin);
		return 1;
	}
	
	off_t data_size = file_size - AES_BLOCK_SIZE;
	
	if (lseek(fin, 0, SEEK_SET) == -1) {
		perror("Failed to seek set 0");
		close(fin);
		return 1;
	}
	
	int fout = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
	
	if (fout == -1) {
		perror("Failed to open output file");
		close(fin);
		return 1;
	}
	
	size_t len;
	uint8_t chunk[CHUNK_SIZE];
	AES_CTX ctx;
	AES_DecryptInit(&ctx, key, key);
	
	while (data_size > 0) {
		len = data_size < CHUNK_SIZE ? data_size : CHUNK_SIZE;
		
		if (read(fin, chunk, len) != len) {
			perror("Failed to read input file");
			close(fin);
			close(fout);
			return 1;
		}
		
		DecryptData(chunk, len, &ctx);
		
		if (write(fout, chunk, len) != len) {
			perror("Failed to write output file");
			close(fin);
			close(fout);
			return 1;
		}
		
		data_size -= len;
	}
	
	if (read(fin, chunk, AES_BLOCK_SIZE) != AES_BLOCK_SIZE) {
		perror("Failed to read final block from input file");
		close(fin);
		close(fout);
		return 1;
	}
	
	DecryptData(chunk, AES_BLOCK_SIZE, &ctx);
	
	size_t padding_size = chunk[AES_BLOCK_SIZE - 1];
	
	if (padding_size > AES_BLOCK_SIZE) {
		fprintf(stderr, "Invalid padding length\n");
		close(fin);
		close(fout);
		return 1;
	}
	
	if (write(fout, chunk, AES_BLOCK_SIZE - padding_size) != AES_BLOCK_SIZE - padding_size) {
		perror("Failed to write final decrypted block to output file");
		close(fin);
		close(fout);
		return 1;
	}
	
	close(fin);
	close(fout);
	return 0;
}
