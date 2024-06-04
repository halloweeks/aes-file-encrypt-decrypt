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

#define CHUNK_SIZE 65536 // Size of each chunk to be read from the file

// Function to decrypt a chunk of data using AES-128-CBC
void DecryptData(AES_CTX *ctx, uint8_t *data, uint32_t size) {
    for (uint32_t offset = 0; offset < size; offset += 16) {
        AES_Decrypt(ctx, data + offset, data + offset); // Decrypt 16 bytes at a time
    }
}

// Function to calculate the number of chunks needed to process the file
uint32_t num_of_blocks(uint64_t size) {
    return (size / CHUNK_SIZE) + (size % CHUNK_SIZE != 0 ? 1 : 0);
}

// Function to get the size of a file
int64_t fsize(const char *filename) {
    struct stat st;
    if (stat(filename, &st) == 0)
        return st.st_size; // Return file size if successful
    else
        return -1; // Return -1 if file not found or other error occurs
}

int main(int argc, const char *argv[]) {
    // Check for correct number of command-line arguments
    if (argc != 3) {
        printf("Usage: %s <input file> <output file>\n", argv[0]);
        return 1;
    }

    uint8_t key[AES_KEY_SIZE];
    memset(key, 0x11, AES_KEY_SIZE); // Initialize the AES key with 0x11111111111111111111111111111111

    // Open the input file for reading
    int fin = open(argv[1], O_RDONLY);
    if (fin == -1) {
        perror("Failed to open input file");
        return 1;
    }

    // Get the size of the input file
    int64_t file_size = fsize(argv[1]);
    if (file_size == -1) {
        perror("Failed to get file size");
        close(fin);
        return 1;
    }

    // Check if the file is empty
    if (file_size == 0) {
        fprintf(stderr, "empty file!\n");
        close(fin);
        return 1;
    }

    // Open the output file for writing
    int fout = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fout == -1) {
        perror("Failed to open output file");
        close(fin);
        return 1;
    }

    ssize_t len;
    uint8_t chunk[CHUNK_SIZE]; // Buffer to hold each chunk of data
    AES_CTX ctx;
    AES_DecryptInit(&ctx, key, key); // Initialize AES context for decryption

    // Calculate the number of full chunks (blocks) to process
    int32_t numBlocks = num_of_blocks(file_size);
    numBlocks -= 1; // Subtract one for the last (possibly partial) block

    // Process all full chunks
    for (uint32_t x = 0; x < numBlocks; x++) {
        read(fin, chunk, CHUNK_SIZE); // Read a chunk from the input file
        DecryptData(&ctx, chunk, CHUNK_SIZE); // Decrypt the chunk
        write(fout, chunk, CHUNK_SIZE); // Write the decrypted chunk to the output file
    }

    // Process the last block, which may be partial
    len = read(fin, chunk, CHUNK_SIZE); // Read the last chunk from the input file
    DecryptData(&ctx, chunk, len); // Decrypt the last chunk

    // Remove PKCS#7 padding
    size_t padding_size = chunk[len - 1];
    len -= padding_size;

    // Write the final decrypted chunk to the output file
    write(fout, chunk, len);

    // Close the input and output files
    close(fin);
    close(fout);
    return 0;
}