#ifndef ENCRYPTOR_H
#define ENCRYPTOR_H

#include <string>

bool encrypt_file(const std::string &in_path, const std::string &out_path, const std::string &passphrase);

#endif

