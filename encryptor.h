#ifndef ENCRYPTOR_H
#define ENCRYPTOR_H

#include <string>

bool encrypt_file_multithreaded(const std::string &in_path,
                                const std::string &out_path,
                                const std::string &passphrase,
                                int num_threads = 4);

#endif

