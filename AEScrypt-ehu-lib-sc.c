/* *
* @file     AEScrypt-ehu-lib-sc.c
* @author   Gonzalo Alvarez - Dpto. ATC/KAT - UPV-EHU
* @date     05/02/2025
* @brief    C file  with encrypt_aes() and decrypt_aes() 256-bit AES functions.
* @details  A C file with two functions my_encript() and my_dencript() 
*           Each function performs encryption or decryption of a data file 
*           using 256-bit AES encryption in CBC mode.
* */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "my_AEScrypt-header.h"

#define handleErrors() { close(fd_infile); close(fd_outfile); ERR_print_errors_fp(stderr); \
	return EVP_CIPHER_CTX_ERROR;}


int my_EncryptFileFunction (const char *input_filename, const char *output_filename, 
                    const unsigned char *key, const unsigned char *iv) 
{
    int  fd_infile, fd_outfile; 
    unsigned char inbuf[READ_BLOCK_SIZE], outbuf[READ_BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;
    unsigned char ErrorMSG[256];
    EVP_CIPHER_CTX *ctx;

    // Open input file for read 
    fd_infile = open(input_filename, O_RDONLY);
    printf("File %s  fd_infile %d, \n", input_filename, fd_infile);
    if (fd_infile == -1) {
        sprintf(ErrorMSG,"Error opening input file (%s)",input_filename);
        perror(ErrorMSG);
        return(ERROR_OPEN_DAT_FILE);
    }

    // Open output file for write 
    fd_outfile = open(output_filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd_outfile == -1) {
         close(fd_infile);
         sprintf(ErrorMSG,"Error opening output file (%s)",output_filename);
         perror(ErrorMSG);
         return(ERROR_OPEN_ENCRYPT_FILE);
    }

    // Create and initialise the context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        close(fd_infile);
        close(fd_outfile);
        handleErrors();
    }

    //  Initialise the encryption operation.
    if ( EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        close(fd_infile);
        close(fd_outfile);
        handleErrors();
    }

    // Encrypt input file contents to output file
    while ((inlen = read(fd_infile, inbuf, READ_BLOCK_SIZE)) > 0) {
        // Provide the message to be encrypted, and obtain the encrypted output.
        if ( EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) !=1) { 
            close(fd_infile);
            close(fd_outfile);
            handleErrors();
        }
        write(fd_outfile, outbuf, outlen);
    }

    // Encryption completion phase. 
    // Further ciphertext bytes may be written at this stage.
    if ( EVP_EncryptFinal_ex(ctx, outbuf, &outlen) !=1) {
        close(fd_infile);
        close(fd_outfile);
        handleErrors();
    }
    write(fd_outfile, outbuf, outlen);

    // close input and output files
    close(fd_infile);
    close(fd_outfile);

    // Clean up the context
    EVP_CIPHER_CTX_free(ctx);
    return OK;
}


int my_DecryptFileFunction (const char *input_filename, const char *output_filename, 
                    const unsigned char *key, const unsigned char *iv) 
{
    int  fd_infile, fd_outfile;     // File Descrptors
    unsigned char inbuf[READ_BLOCK_SIZE], outbuf[READ_BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;
    unsigned char ErrorMSG[256];

    EVP_CIPHER_CTX *ctx;


    // Open input file for read (encrypted file)
    fd_infile = open(input_filename, O_RDONLY);
    if (fd_infile == -1) {
        sprintf(ErrorMSG,"Error opening input file (%s)",input_filename);
        perror(ErrorMSG);
        return(ERROR_OPEN_DAT_FILE);
    }

    // Open output file for write 
    fd_outfile = open(output_filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd_outfile == -1) {
         close(fd_infile);
         sprintf(ErrorMSG,"Error opening output file (%s)",output_filename);
         perror(ErrorMSG);
         return(ERROR_OPEN_ENCRYPT_FILE);
    }

    // Create and initialise the context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        close(fd_infile);
        close(fd_outfile);
        handleErrors();
    }

    //  Initialise the Decryption operation.
    if ( EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) !=1) {
        close(fd_infile);
        close(fd_outfile);
        handleErrors();
    }
 
    // Dencrypt input file contents to output file
    while ((inlen = read(fd_infile, inbuf, READ_BLOCK_SIZE)) > 0) {
        // Provide the encripted message to be decrypted, and obtain the original data.
        if ( EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) !=1) { 
            close(fd_infile);
            close(fd_outfile);
            handleErrors();
        }
        write(fd_outfile, outbuf, outlen);
    }

    // Decryption completion phase. 
    // Further ciphertext bytes may be written at this stage.
    if ( EVP_DecryptFinal_ex(ctx, outbuf, &outlen) !=1) {
        close(fd_infile);
        close(fd_outfile);
        handleErrors();
    }
    write(fd_outfile, outbuf, outlen);

 
    // close input and output files   
    close(fd_infile);
    close(fd_outfile);

    // Clean up the context
    EVP_CIPHER_CTX_free(ctx);
    return OK;
}
