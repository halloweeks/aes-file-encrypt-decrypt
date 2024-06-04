#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdlib.h>
#include "AES_128_CBC.h"

#define CHUNK_SIZE 65536 // Size of each chunk to be read from the file

int main(int argc, const char *argv[]) {
    // Check for correct number of command-line arguments
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input file> <output file>\n", argv[0]);
        return 1;
    }

    uint8_t key[AES_KEY_SIZE];
    memset(key, 0x11, AES_KEY_SIZE); // Initialize the AES key with a constant value

    // Open the input file for reading
    int fin = open(argv[1], O_RDONLY);
    if (fin == -1) {
        printf("Failed to open input file!\n");
        return 1;
    }

    // Open the output file for writing
    int fout = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fout == -1) {
        printf("Failed to open output file!\n");
        close(fin);
        return 1;
    }

    uint8_t chunk[CHUNK_SIZE + AES_BLOCK_SIZE]; // Buffer to hold each chunk of data
    AES_CTX ctx;
    AES_EncryptInit(&ctx, key, key /*iv*/); // Initialize AES context for encryption

    ssize_t len;

    // Read data from input file, encrypt it, and write to output file in chunks
    while ((len = read(fin, chunk, CHUNK_SIZE)) > 0) {
        // Pad the last block with PKCS#7 padding if necessary
        if (len % AES_BLOCK_SIZE != 0) {
            uint8_t padding_size = AES_BLOCK_SIZE - (len % AES_BLOCK_SIZE);
            memset(chunk + len, padding_size, padding_size);
            len += padding_size;
        }
        AES_Encrypt(&ctx, chunk, len, chunk); // Encrypt the chunk
        write(fout, chunk, len); // Write the encrypted chunk to the output file
    }

    // Close the input and output files
    close(fin);
    close(fout);
    return 0;
}
