#include "decryptor.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <fstream>
#include <vector>
#include <iostream>
#include <cstring>

static const int AES_KEY_LEN = 16;   // 128 bits
static const int AES_BLOCK_SIZE = 16;
static const size_t BUFFER_SIZE = 4096;

void derive_key_dec(const std::string &pass, unsigned char key[AES_KEY_LEN]) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)pass.data(), pass.size(), hash);
    memcpy(key, hash, AES_KEY_LEN);
}

bool decrypt_file(const std::string &in_path, const std::string &out_path, const std::string &passphrase) {
    std::ifstream infile(in_path, std::ios::binary);
    if (!infile) { std::cerr << "Cannot open input file\n"; return false; }

    unsigned char iv[AES_BLOCK_SIZE];
    infile.read((char*)iv, sizeof(iv));
    if (infile.gcount() != sizeof(iv)) {
        std::cerr << "Invalid file format (no IV)\n";
        return false;
    }

    std::ofstream outfile(out_path, std::ios::binary);
    if (!outfile) { std::cerr << "Cannot open output file\n"; return false; }

    unsigned char key[AES_KEY_LEN];
    derive_key_dec(passphrase, key);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv)) {
        std::cerr << "DecryptInit failed\n";
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
            if (1 != EVP_DecryptUpdate(ctx, outbuf.data(), &outlen,
                                       inbuf.data(), (int)read_bytes)) {
                std::cerr << "DecryptUpdate failed\n";
                EVP_CIPHER_CTX_free(ctx);
                return false;
            }
            outfile.write((char*)outbuf.data(), outlen);
        }
    }

    if (1 != EVP_DecryptFinal_ex(ctx, outbuf.data(), &outlen)) {
        std::cerr << "DecryptFinal failed (wrong key or corrupted file)\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    outfile.write((char*)outbuf.data(), outlen);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

