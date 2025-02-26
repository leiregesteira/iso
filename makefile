CC       = gcc
CFLAGS   = -I. -g 
DEPS     = my_AEScrypt-header.h
OBJFILES = AEScrypt-ehu-lib-sc.o AEScrypt-repo.o InsertAndEncryptFile.o
EXEC     = my_AES-repo-app

all: $(EXEC)

$(EXEC) : $(OBJFILES)
	$(CC) $(OBJFILES)  -o $(EXEC) -g -lssl -lcrypto

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS)  -c -g -o $@ $< 

clean:
	rm -f $(OBJFILES) $(EXEC)

