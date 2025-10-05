#ifndef DECRYPTOR_H
#define DECRYPTOR_H

#include <string>

bool decrypt_file(const std::string &in_path, const std::string &out_path, const std::string &passphrase);

#endif

