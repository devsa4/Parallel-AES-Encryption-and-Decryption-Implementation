#include "encryptor.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <fstream>
#include <vector>
#include <iostream>
#include <cstring>
using namespace std;
static const int AES_KEY_LEN = 16;  
static const int AES_BLOCK_SIZE = 16;
struct ThreadData {
    vector<unsigned char> input;
    vector<unsigned char> output;
    unsigned char key[AES_KEY_LEN];
    unsigned char iv[AES_BLOCK_SIZE];
    bool success = false;
};
void derive_key(const std::string &pass, unsigned char key[AES_KEY_LEN]) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)pass.data(), pass.size(), hash);
    memcpy(key, hash, AES_KEY_LEN);
}
void* encrypt_chunk(void* arg) {
    ThreadData* td = (ThreadData*)arg;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return nullptr;
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, td->key, td->iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return nullptr;
    }
    td->output.resize(td->input.size() + AES_BLOCK_SIZE);
    int out1 = 0, out2 = 0;
    if (1 != EVP_EncryptUpdate(ctx, td->output.data(), &out1,
                               td->input.data(), (int)td->input.size())) {
        EVP_CIPHER_CTX_free(ctx);
        return nullptr;
    }
    if (1 != EVP_EncryptFinal_ex(ctx, td->output.data() + out1, &out2)) {
        EVP_CIPHER_CTX_free(ctx);
        return nullptr;
    }
    td->output.resize(out1 + out2);
    td->success = true;
    EVP_CIPHER_CTX_free(ctx);
    return nullptr;
}
bool encrypt_file_multithreaded(const string &in_path,
                                const string &out_path,
                                const string &passphrase,
                                int num_threads) {
    ifstream in(in_path, std::ios::binary | std::ios::ate);
    if (!in) { std::cerr << "Cannot open input\n"; return false; }
    size_t filesize = in.tellg();
    in.seekg(0);
    ofstream out(out_path, std::ios::binary);
    if (!out) { std::cerr << "Cannot open output\n"; return false; }
    unsigned char key[AES_KEY_LEN];
    derive_key(passphrase, key);
    size_t chunk_size = (filesize + num_threads - 1) / num_threads;
    vector<ThreadData> td(num_threads);
    vector<pthread_t> tids(num_threads);
    for (int i = 0; i < num_threads; ++i) {
        size_t start = i * chunk_size;
        if (start >= filesize) { num_threads = i; break; }
        size_t this_chunk = min(chunk_size, filesize - start);
        td[i].input.resize(this_chunk);
        in.read((char*)td[i].input.data(), this_chunk);
        memcpy(td[i].key, key, AES_KEY_LEN);
        RAND_bytes(td[i].iv, AES_BLOCK_SIZE);
        pthread_create(&tids[i], nullptr, encrypt_chunk, &td[i]);
    }
    for (int i = 0; i < num_threads; ++i) {
        pthread_join(tids[i], nullptr);
        if (!td[i].success) {
            cerr << "Chunk " << i << " failed\n";
            return false;
        }
        uint64_t sz = td[i].output.size();
        out.write((char*)td[i].iv, AES_BLOCK_SIZE);
        out.write((char*)&sz, sizeof(sz));
        out.write((char*)td[i].output.data(), sz);
    }
    return true;
}
