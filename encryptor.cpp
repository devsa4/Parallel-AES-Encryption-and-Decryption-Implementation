#include "encryptor.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <fstream>
#include <vector>
#include <iostream>
#include <cstring>

static const int AES_KEY_LEN = 16;   // 128 bits
static const int AES_BLOCK_SIZE = 16;
static const size_t BUFFER_SIZE = 4096;

void derive_key(const std::string &pass, unsigned char key[AES_KEY_LEN]) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)pass.data(), pass.size(), hash);
    memcpy(key, hash, AES_KEY_LEN);
}

bool encrypt_file(const std::string &in_path, const std::string &out_path, const std::string &passphrase) {
    std::ifstream infile(in_path, std::ios::binary);
    if (!infile) { std::cerr << "Cannot open input file\n"; return false; }

    std::ofstream outfile(out_path, std::ios::binary);
    if (!outfile) { std::cerr << "Cannot open output file\n"; return false; }

    unsigned char key[AES_KEY_LEN];
    derive_key(passphrase, key);

    unsigned char iv[AES_BLOCK_SIZE];
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        std::cerr << "IV generation failed\n";
        return false;
    }

    outfile.write((char*)iv, sizeof(iv));

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv)) {
        std::cerr << "EncryptInit failed\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    std::vector<unsigned char> inbuf(BUFFER_SIZE);
    std::vector<unsigned char> outbuf(BUFFER_SIZE + AES_BLOCK_SIZE);
    int outlen;

    while (infile.good()) {
        infile.read((char*)inbuf.data(), inbuf.size());
        std::streamsize read_bytes = infile.gcount();
        if (read_bytes > 0) {
            if (1 != EVP_EncryptUpdate(ctx, outbuf.data(), &outlen,
                                       inbuf.data(), (int)read_bytes)) {
                std::cerr << "EncryptUpdate failed\n";
                EVP_CIPHER_CTX_free(ctx);
                return false;
            }
            outfile.write((char*)outbuf.data(), outlen);
        }
    }

    if (1 != EVP_EncryptFinal_ex(ctx, outbuf.data(), &outlen)) {
        std::cerr << "EncryptFinal failed\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    outfile.write((char*)outbuf.data(), outlen);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

