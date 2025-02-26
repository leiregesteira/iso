/* *
* @file     AEScrypt-repo.c
* @author   Gonzalo Alvarez - Dpto. ATC/KAT - UPV-EHU
* @date     05/02/2025
* @brief    First version of AEScrypt-repo application
* @details  This app create a Repo file with the data structure definition 
*           (c_AEScrypt_header) and an encripted file with a 256-bit AES 
*           encryption in CBC mode.. 
* */

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "my_AEScrypt-header.h"

//#define KEY_SIZE 32
//#define IV_SIZE 16

extern int my_EncryptFileFunction(const char *input_filename, const char *output_filename, 
                                  const unsigned char *key, const unsigned char *iv);
                                  
extern int my_DecriptFileFunction(const char *input_filename, const char *output_filename,
                                  const unsigned char *key, const unsigned char *iv);
extern int InsertAndEncryptFile(const char *RepoFileName, const char *SourceFileName);

// Build c_EVP_AEScrypt_header structure with FileName (fill a new c_EVP_AEScrypt_header)
int BuilEVP_AEScryptRepoHeader(char *OrigFileName, char *EncryptFileName, off_t OrigFileSize, off_t EncryptFileSize,
                              char *my_EVP_AES_256_Key,  char *my_EVP_AES_IV_Key,  
                              struct s_EVP_AES_RepoHeader *pevp_aes_header    )                   
{
    int Return_Code;

   // Fill all struct pevp_aes_header members
        
   bzero(pevp_aes_header, sizeof(pevp_aes_header));     // Fill all struct data with zeros

   strcpy(pevp_aes_header->fOrigName, OrigFileName);        // Original file name
   strcpy(pevp_aes_header->fEncryptName, EncryptFileName);   // Encrypted file name

   pevp_aes_header->OrigFileSize = OrigFileSize;                  // At the moment it is an unknown value
   pevp_aes_header->EncryptFileSize = EncryptFileSize;               // At the moment it is an unknown value
                                                    // Later we can fill it in
   // Fill the EVP_AES_KEY and EVP_AES_IV keys
   memcpy(pevp_aes_header->EVP_AES_KEY, my_EVP_AES_256_Key, EVP_AES_256_KEY_SIZE);                                  
   memcpy(pevp_aes_header->EVP_AES_IV, my_EVP_AES_IV_Key, EVP_AES_256_IV_SIZE);   
   
   // to complete in subsequent versions of the project                                
    
   return HEADER_OK;
}
extern int InsertAndEncrypFile(const char *RepoFileName, const char *SourceFileName);

int main(int argc, char *argv[])
{
    char SourceFileName[256];       // Original SouceFile
    char TmpCryptFileName[256];     // Encrypted data of SourceFileName
    char RepoFileName[256];         // Repository file name
    char my_EVP_AES_Key[EVP_AES_256_KEY_SIZE];
    char my_AES_IV_Key[EVP_AES_256_IV_SIZE];
    struct s_EVP_AES_RepoHeader my_AES_RepoHeader;
    
    char FileDataBlock[READ_BLOCK_SIZE];
    
    char accion[1]; //I (Insertar)/E (Extraer)
    int i,ret, Tam;
    int fd_RepoFile, ins_prueba;
    unsigned long RepoFileSize, n, offset;
    // ------------------------------------------------------------------------------
    // Control of the number of arguments.
    // For the moment the keys will be fixed values.
    if (argc !=4) {
        fprintf(stderr,"Use: %s SourceFilename     RepoAES256FileName  I/E \n", argv[0]);
        return 1;
    }
    strcpy(SourceFileName, argv[1]);  // Source data File
    sprintf(TmpCryptFileName,"%s.crypt",SourceFileName);  // Generated encrypted file
    
    strcpy(RepoFileName, argv[2]);                   // Repository file name 

    strcpy(accion, argv[3]);


	if (strcmp(accion, "I")==0){
		ins_prueba= InsertAndEncryptFile(RepoFileName, SourceFileName);
		        printf("\nArchivo %s insertado con éxito en el repositorio %s 🥳\nNúmero de archivos en el repositorio: %d\n\n", SourceFileName, RepoFileName, ins_prueba);
	} else {
		        fprintf(stderr,"Invalid value for parameter [action]; Expected 'I' or 'E' but %s given\n", accion);
	}
    // ----------------------------------------------------------------
    // (1.1) open EVP_AEScryptRepo Repository File  
    //   File name: RepoFileName i
    //   Flags:  O_WRONLY | O_CREAT | O_TRUNC
    //   Mode : 0600
    //  To complete the code 
    /// vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
/**	fd_RepoFile = open(RepoFileName, O_WRONLY|O_CREAT|O_TRUNC, 0600);
	if(fd_RepoFile == -1){
		fprintf(stderr,"Error al abrir el fichero %s.\n", RepoFileName);
       		exit(ERROR_OPEN_DAT_FILE);
	}
    
    
        fprintf(stderr,"Invalid value for parameter [action]; Expected 'I' or 'E' but %s given\n", action);    /// ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^


    // ----------------------------------------------------------------
    // (1.2)Write  my_EVP_AES_header  (of FileName) to the Repository File (RepoFileName)
    RepoFileSize = 0;
    
    //  To complete the code 
    /// vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
	n = write(fd_RepoFile, &my_AES_RepoHeader, sizeof(my_AES_RepoHeader)); 
		if(n != sizeof(my_AES_RepoHeader)){
		fprintf(stderr,"Error al abrir el fichero %s.\n", RepoFileName);
                exit(ERROR_ENCRIPTING_FILE);

	}  


    
    /// ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    RepoFileSize = RepoFileSize +n;       // Update  RepoFileSize file size
    printf(" (my_AES_RepoHeader ) written %ld bytes to file %s \n", n, RepoFileName); // Traze


    // ----------------------------------------------------------------
    // (1.3) Create the Encrypted data file (TmpCryptFileName) 
    //
    //   Call to EncryptFile Function 
    //
    // ----------------------------------------------------------------
    
    if (my_EncryptFileFunction(SourceFileName, TmpCryptFileName, my_EVP_AES_Key, my_AES_IV_Key ))
    {
        fprintf(stderr,"Cannot Encrypt  %s to %s \n", SourceFileName,TmpCryptFileName);
        return ERROR_ENCRIPTING_FILE;
    }

    // -------------------------------------------------------------
    // (1.4) Close  Repository Files 
    //  To complete the code 
    /// vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
	close(fd_RepoFile);	   
 

    /// ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  
    // Final message to user
    printf("%s (RepoFileName) and %s (encrypedfile)  of %s data file  has been generated \n", 
              RepoFileName, TmpCryptFileName, SourceFileName);   

    return OK;		// (OK=0)
**/
}
