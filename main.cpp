#include <iostream>
#include <string>
#include "encryptor.h"
#include "decryptor.h"

int main() {
    std::string filepath;
    std::string passphrase;
    int choice;

    std::cout << "Enter path of file: ";
    std::getline(std::cin, filepath);

    std::cout << "Enter passphrase: ";
    std::getline(std::cin, passphrase);

    std::cout << "Choose operation:\n1. Encrypt\n2. Decrypt\n> ";
    std::cin >> choice;

    if (choice == 1) {
        std::string outpath = filepath + ".enc";
        if (encrypt_file(filepath, outpath, passphrase)) {
            std::cout << "File encrypted successfully -> " << outpath << std::endl;
        } else {
            std::cout << "Encryption failed!" << std::endl;
        }
    } else if (choice == 2) {
        std::string outpath = filepath + ".dec";
        if (decrypt_file(filepath, outpath, passphrase)) {
            std::cout << "File decrypted successfully -> " << outpath << std::endl;
        } else {
            std::cout << "Decryption failed!" << std::endl;
        }
    } else {
        std::cout << "Invalid choice!" << std::endl;
    }

    return 0;
}

