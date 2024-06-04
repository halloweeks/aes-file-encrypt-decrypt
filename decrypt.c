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
    int64_t file_size = lseek(fin, 0, SEEK_END);
    lseek(fin, 0, SEEK_SET);
    
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
    
    uint8_t chunk[CHUNK_SIZE]; // Buffer to hold each chunk of data
    AES_CTX ctx;
    AES_DecryptInit(&ctx, key, key /*iv*/); // Initialize AES context for decryption

    // Calculate the number of full chunks (blocks) to process
    int32_t numBlocks = (file_size / CHUNK_SIZE) + (file_size % CHUNK_SIZE != 0 ? 1 : 0);
    numBlocks -= 1; // Subtract one for the last (possibly partial) block
    
    // Process all full chunks
    for (uint32_t x = 0; x < numBlocks; x++) {
        read(fin, chunk, CHUNK_SIZE); // Read a chunk from the input file
        AES_Decrypt(&ctx, chunk, CHUNK_SIZE, chunk); // Decrypt the chunk
        write(fout, chunk, CHUNK_SIZE); // Write the decrypted chunk to the output file
    }

    // Process the last block, which may be partial
    int len = read(fin, chunk, CHUNK_SIZE); // Read the last chunk from the input file
    AES_Decrypt(&ctx, chunk, len, chunk); // Decrypt the last chunk
    
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