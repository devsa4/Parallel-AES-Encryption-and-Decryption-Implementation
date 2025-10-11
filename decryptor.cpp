#include "decryptor.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <fstream>
#include <vector>
#include <iostream>
#include <cstring>

static const int AES_KEY_LEN = 16;
static const int AES_BLOCK_SIZE = 16;

struct ThreadData {
    std::vector<unsigned char> input;
    std::vector<unsigned char> output;
    unsigned char key[AES_KEY_LEN];
    unsigned char iv[AES_BLOCK_SIZE];
    bool success = false;
};

void derive_key_dec(const std::string &pass, unsigned char key[AES_KEY_LEN]) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)pass.data(), pass.size(), hash);
    memcpy(key, hash, AES_KEY_LEN);
}

void* decrypt_chunk(void* arg) {
    ThreadData* td = (ThreadData*)arg;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return nullptr;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, td->key, td->iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return nullptr;
    }

    td->output.resize(td->input.size() + AES_BLOCK_SIZE);
    int out1 = 0, out2 = 0;
    if (1 != EVP_DecryptUpdate(ctx, td->output.data(), &out1,
                               td->input.data(), (int)td->input.size())) {
        EVP_CIPHER_CTX_free(ctx);
        return nullptr;
    }
    if (1 != EVP_DecryptFinal_ex(ctx, td->output.data() + out1, &out2)) {
        EVP_CIPHER_CTX_free(ctx);
        return nullptr;
    }
    td->output.resize(out1 + out2);
    td->success = true;
    EVP_CIPHER_CTX_free(ctx);
    return nullptr;
}

bool decrypt_file_multithreaded(const std::string &in_path,
                                const std::string &out_path,
                                const std::string &passphrase,
                                int num_threads) {
    std::ifstream in(in_path, std::ios::binary);
    if (!in) { std::cerr << "Cannot open input\n"; return false; }
    std::ofstream out(out_path, std::ios::binary);
    if (!out) { std::cerr << "Cannot open output\n"; return false; }

    unsigned char key[AES_KEY_LEN];
    derive_key_dec(passphrase, key);

    std::vector<ThreadData> td(num_threads);
    std::vector<pthread_t> tids(num_threads);

    int i = 0;
    while (true) {
        if (in.peek() == EOF) break;
        if (i >= num_threads) num_threads = i; 

        ThreadData &t = td[i];
        memcpy(t.key, key, AES_KEY_LEN);
     
        in.read((char*)t.iv, AES_BLOCK_SIZE);
        if (in.gcount() != AES_BLOCK_SIZE) break;

        uint64_t sz = 0;
        in.read((char*)&sz, sizeof(sz));
        if (in.gcount() != sizeof(sz)) break;

        t.input.resize(sz);
        in.read((char*)t.input.data(), sz);
        if ((uint64_t)in.gcount() != sz) break;

        pthread_create(&tids[i], nullptr, decrypt_chunk, &t);
        ++i;
    }

    for (int j = 0; j < i; ++j) {
        pthread_join(tids[j], nullptr);
        if (!td[j].success) {
            std::cerr << "Decryption failed for chunk " << j << "\n";
            return false;
        }
        out.write((char*)td[j].output.data(), td[j].output.size());
    }
    return true;
}

