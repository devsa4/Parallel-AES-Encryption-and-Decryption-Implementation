#include <iostream>
#include <string>
#include "encryptor.h"
#include "decryptor.h"

int main() {
    std::string filepath;
    std::string passphrase;
    int choice;
    int num_threads = 4; // default thread count

    std::cout << "Enter path of file: ";
    std::getline(std::cin, filepath);

    std::cout << "Enter passphrase: ";
    std::getline(std::cin, passphrase);

    std::cout << "Choose operation:\n1. Encrypt\n2. Decrypt\n> ";
    std::cin >> choice;

    std::cout << "Enter number of threads (default 4): ";
    std::cin >> num_threads;
    if (num_threads <= 0) num_threads = 4;

    if (choice == 1) {
        std::string outpath = filepath + ".enc";
        if (encrypt_file_multithreaded(filepath, outpath, passphrase, num_threads)) {
            std::cout << "File encrypted successfully -> " << outpath << std::endl;
        } else {
            std::cout << "Encryption failed!" << std::endl;
        }
    } else if (choice == 2) {
        std::string outpath = filepath + ".dec";
        if (decrypt_file_multithreaded(filepath, outpath, passphrase, num_threads)) {
            std::cout << "File decrypted successfully -> " << outpath << std::endl;
        } else {
            std::cout << "Decryption failed!" << std::endl;
        }
    } else {
        std::cout << "Invalid choice!" << std::endl;
    }

    return 0;
}

