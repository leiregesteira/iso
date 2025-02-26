/**
* @file     my_AEScrypt-header.h
* @author   Gonzalo Alvarez - Dpto. ATC/KAT - UPV-EHU
* @date     05/02/2025
* @brief    Include file with struct c_AEScrypt_header
* @details  A header file(.h) with the data structure definition 
*           (c_AEScrypt_header). This file will be used to create a  
*           "special file" that will store information about a set
*           of files, encrypted with AES-256 :
*  
*                "SPECIAL  FILE"
*           +++++++++++++++++++++++++++++++++
*           + Header File Record    0       +
*           +-------------------------------+
*           + Header File Record   1        +
*           +-------------------------------+
*           +             ...               +
*           +++++++++++++++++++++++++++++++++
*           + Header File Record K-1        +
*           +++++++++++++++++++++++++++++++++
* 
*/
#include <stddef.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define OK (0)
#define ERROR_WRONG_NUMBER_ARGUMENTS (1)
#define ERROR_GENERATE_MY_EVP_AES_HEADER (2)
#define ERROR_OPEN_DAT_FILE (3)
#define ERROR_OPEN_ENCRYPT_FILE (4)
#define ERROR_OPEN_AEScrypt_REPO_FILE (5)
#define EVP_CIPHER_CTX_ERROR (6)
#define ERROR_AES_IV_KEY_TOO_SHORT (7)
#define ERROR_READ_AES_REPO_HEADR (8)
#define ERROR_ENCRIPTING_FILE   (9)
#define ERROR_OPERATION_ARGUMENT   (10)
#define ERROR_SOURCEFILE_NOT_INSIDE_REPO   (11)
#define ERROR_DECRIPTING_FILE   (12)

#define ERROR_OTHER_1 (20)
#define ERROR_OTHER_2 (21)

#define FILE_HEADER_SIZE        1024
#define READ_BLOCK_SIZE     (1024)                     // 1 KBytes

// Return error Codes
#define HEADER_OK (1)
#define HEADER_ERR (2)

#define EVP_AES_256_KEY_SIZE 32  // AES256 KEY   :32 bytes
#define EVP_AES_256_IV_SIZE  16  // AES256 IV    :16 bytes

// To minimaze errors this KEYs . Very bad idea (very unsafe) 
#define BAD_AES256_KEY  "This is a very bad key 012345678"
#define BAD_IV          "Very bad IV 0123"


// EVP Symmetric Encryption and Decryption
// https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
// https://docs.openssl.org/master/man3/EVP_EncryptInit/#description

// This is an aproximation size y bytes
#define DATA_VALID_SIZE ( 2*256 + 2*sizeof(off_t) + EVP_AES_256_KEY_SIZE + EVP_AES_256_IV_SIZE )    
#define UNUSED_DATA_SIZE ( FILE_HEADER_SIZE - DATA_VALID_SIZE)   


struct s_EVP_AES_RepoHeader {
        char fOrigName[256];                      // Original file name
        char fEncryptName[256];                   // Encrypted file name
        off_t OrigFileSize;                       // Original File size (off_t is similar to a  integer)
        off_t EncryptFileSize;                    // Encrypted File size (off_t is similar to a  integer)
        char EVP_AES_KEY[EVP_AES_256_KEY_SIZE];   // AES256 KEY  :32 bytes
        char EVP_AES_IV[EVP_AES_256_IV_SIZE];     // AES256 IV   :16 bytes
        //...
        // to complete in subsequent versions of the project
        char unused[UNUSED_DATA_SIZE];
};



/**
* end @file my_AEScrypt-header.h
**/
