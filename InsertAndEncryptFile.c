#include "my_AEScrypt-header.h"

int InsertAndEncryptFile(const char *RepoFileName, const char *SourceFileName){

    //char SourceFileName[256];       // Original SourceFile
    char TmpCryptFileName[256];     // Encrypted data of SourceFileName
    //char RepoFileName[256];         // Repository file name
    char my_EVP_AES_Key[EVP_AES_256_KEY_SIZE];
    char my_AES_IV_Key[EVP_AES_256_IV_SIZE];
    struct s_EVP_AES_RepoHeader my_AES_RepoHeader;
    
    char FileDataBlock[READ_BLOCK_SIZE];
    
    int i,ret, Tam;
    int fd_RepoFile;
    unsigned long RepoFileSize, n, offset, rn;

    // ------------------------------------------------------------------------------
    // For the moment the keys will be fixed values.
    sprintf(TmpCryptFileName,"%s.crypt",SourceFileName);  // Generated encrypted file
    
    memcpy(my_EVP_AES_Key, BAD_AES256_KEY, EVP_AES_256_KEY_SIZE); // Bad Idea (unsafe)
    memcpy(my_AES_IV_Key, BAD_IV, EVP_AES_256_IV_SIZE); // Bad Idea  (unsafe)
    //
    // ------------------------------------------------------------------------------

    // ------------------------------------------------------------------------------
    // (1.0) Build  my_AES_RepoHeader structure with FileName info
    // For the moment OrigFileSize and EncryptFileSize
    bzero(& my_AES_RepoHeader, sizeof( my_AES_RepoHeader));
    ret = BuilEVP_AEScryptRepoHeader(SourceFileName, TmpCryptFileName, 0, 0, my_EVP_AES_Key, 
                                     my_AES_IV_Key,  &my_AES_RepoHeader );
    if (ret !=HEADER_OK)
    {
        fprintf(stderr,"The my_AES_RepoHeader data was not generated correctly\n");
        return ERROR_GENERATE_MY_EVP_AES_HEADER;
    }

    // ----------------------------------------------------------------
    // (1.1) open EVP_AEScryptRepo Repository File  
    //   File name: RepoFileName i
    //   Flags:  O_RDWR | O_CREAT 
    //   Mode : 0600
    //  To complete the code 
    /// vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
	fd_RepoFile = open(RepoFileName, O_RDWR|O_CREAT, 0600);
	if(fd_RepoFile == -1){
		fprintf(stderr,"Error al abrir el fichero %s.\n", RepoFileName);
       		exit(ERROR_OPEN_DAT_FILE);
	}
    
		
    /// ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^


    // ----------------------------------------------------------------
    // (1.2)Write  my_EVP_AES_header  (of FileName) to the Repository File (RepoFileName)
    RepoFileSize = 0;
    	printf("ANTES DEL SEEK");
        if (sizeof(fd_RepoFile)!=0){
                printf("EN EL SEEK");
		if (lseek(fd_RepoFile, 0L, SEEK_END)==-1)
                       fprintf(stderr, "Error al hacer el seek");
	}


        n = write(fd_RepoFile, &my_AES_RepoHeader, sizeof(my_AES_RepoHeader));
                if(n != sizeof(my_AES_RepoHeader)){
                fprintf(stderr,"Error al abrir el fichero %s.\n", RepoFileName);
                exit(ERROR_ENCRIPTING_FILE);

        }
		

    //  To complete the code 
    /// vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
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

}
