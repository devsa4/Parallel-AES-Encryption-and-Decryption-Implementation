#ifndef DECRYPTOR_H
#define DECRYPTOR_H

#include <string>

bool decrypt_file_multithreaded(const std::string &in_path,
                                const std::string &out_path,
                                const std::string &passphrase,
                                int num_threads = 4);

#endif

