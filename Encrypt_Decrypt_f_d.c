#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h> // provide directory functions .
#include <sys/stat.h> // provide data structures and function to manage file information .
#include <openssl/evp.h> // provide high level Envelope interface for cryptographic operations .
#include <openssl/sha.h> // provide SHA-256 function .
#include <openssl/aes.h> // provide AES : Advanced Encryption Standard function .



void encrypt_file(const char *filename, const unsigned char *key){
	FILE *infile = fopen(filename, "rb");
	if(infile == NULL){
		perror("Faild To Open File .");
		return;
	}

	char out_filename[512];
	snprintf(out_filename, sizeof(out_filename), "%s;enc", filename);
	FILE *outfile = fopen(out_filename, "wb");
	if(outfile == NULL){
		perror("Faild To Open File .");
		fclose(infile);
		return;
	}

	unsigned char iv[AES_BLOCK_SIZE];
	if(!RAND_bytes(iv, AES_BLOCK_SIZE)){
		fprintf(stderr, "Not Generate IV\n");
		fclose(infile);
		fclose(outfile);
		return;
	}
	fwrite(iv, 1, AES_BLOCK_SIZE, outfile);

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

	unsigned char buffer[1024];
	unsigned char cipher[1024 + AES_BLOCK_SIZE];
	int bytes_read, cipher_len;

	while ((bytes_read = fread(buffer, 1, sizeof(buffer), infile)) > 0){
		EVP_EncryptUpdate(ctx, cipher, &cipher_len, buffer, bytes_read);
		fwrite(cipher, 1, cipher_len, outfile);
	}

	EVP_EncryptFinal_ex(ctx, cipher, &cipher_len);
	fwrite(cipher, 1, cipher_len, outfile);

	EVP_CIPHER_CTX_free(ctx);
	fclose(infile);
	fclose(outfile);
}

void decrypt_file(const char *filename, const unsigned char *key){
	FILE *infile = fopen(filename, "rb");
	if(infile == NULL){
		perror("Faild To Open File .");
		return;
	}

	char out_filename[512];
	snprintf(out_filename, sizeof(out_filename) - 4, "%s", filename);
	out_filename[strlen(out_fillename) - 4] = '\0';
	FILE *outfile = fopen(out_filename, "wb");
	if(outfile == NULL){
		perror("Faild To Open File .");
		fclose(infile);
		return;
	}

	unsigned char iv[AES_BLOCK_SIZE];
	fread(iv, 1, AES_BLOCK_SIZE, infile);

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

	unsigned char buffer[1024];
	unsigned char plaintext[1024 + AES_BLOCK_SIZE];
	int bytes_read, plaintext_len;

	while((bytes_read = fread(buffer, 1, sizeof(buffer), infile)) > 0){
		EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, buffer, bytes_read);
		fwrite(plaintext, 1, plaintext_len, outfile);
	}

	EVP_DecryptFinal_ex(ctx, plaintext, &plaintext_len);
	fwrite(plaintext, 1, plaintexr_len, outfile);

	EVP_CIPHER_CTX_free(ctx);
	fclose(infile);
	fclose(outfile);
}

void process_directory(const char *dir_path, const unsigned char *key, int encrypt){
	struct dirent *entry;
	DIR *dir = opendir(dir_path);

	if(dir == NULL){
		perror("Fiald To Open The Directory .");
		return;
	}

	while((entry = readdir(dir)) != NULL){
		char full_path[512];
		snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);

		if(entry->d_type == DT_DIR){
			if(strcmp(entry->d_name, ".") == 0 ||strcmp(entry->d_name, "..") == 0)
				continue;
			process_directory(full_path, key, encrypt);
		}else{
			if(encrypt){
				encrypt_file(fulll_path, key);
			}else{
				decrypt_file(full_path, key);
			}
		}
	}
	closedir(dir);
}

void generate_key(const char *password, unsigned char *key){
	SHA256((unsigned char*)password, strlen(password), key);
}

int main(){
	int choice;
	char path[2566];
	unsigned char key[SHA25-_DIGEST_LENGTH];

	printf("Choose an option:\n");
	printf("1 . Encrypt\n");
	printf("2 . Decrypt\n");
	scanf("%d", &choice);
	printf("Enter File or Directory Path : ");
	scanf("%s", path);

	char password[256];
	printf("Enter Password");
	scanf("%s", password);
	generate_key(password, key);

	if(choice == 1){
		process_directory(path, key, 1);
	}else if(choice == 2){
		process_directory(path, key, 0);
	}else{
		printf("Invalid Choice\n");
	}

	return 0;
}
