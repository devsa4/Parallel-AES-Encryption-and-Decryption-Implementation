#include <iostream>
#include <string>
#include <vector>
#include <sys/wait.h>
#include <unistd.h>
#include "encryptor.h"
#include "decryptor.h"

int main() {
    int choice;
    int num_threads = 4;
    std::string passphrase;
    std::vector<std::string> filepaths;

    std::cout << "Choose operation:\n1. Encrypt\n2. Decrypt\n> ";
    std::cin >> choice;
    std::cin.ignore(); // clear newline

    std::cout << "Enter passphrase: ";
    std::getline(std::cin, passphrase);

    std::cout << "Enter number of threads (default 4): ";
    std::cin >> num_threads;
    std::cin.ignore();
    if (num_threads <= 0) num_threads = 4;

    std::cout << "Enter file paths (comma-separated): ";
    std::string input;
    std::getline(std::cin, input);

    // Split input into filepaths
    size_t pos = 0;
    while ((pos = input.find(',')) != std::string::npos) {
        filepaths.push_back(input.substr(0, pos));
        input.erase(0, pos + 1);
    }
    if (!input.empty()) filepaths.push_back(input);

    for (const auto& filepath : filepaths) {
        pid_t pid = fork();
        if (pid == 0) {
            std::string outpath;
            bool success = false;

            if (choice == 1) {
                outpath = filepath + ".enc";
                success = encrypt_file_multithreaded(filepath, outpath, passphrase, num_threads);
            } else if (choice == 2) {
                outpath = filepath + ".dec";
                success = decrypt_file_multithreaded(filepath, outpath, passphrase, num_threads);
            } else {
                std::cerr << "Invalid choice!" << std::endl;
                exit(1);
            }

            if (success) {
                std::cout << "Success -> " << outpath << std::endl;
            } else {
                std::cerr << "Failed -> " << filepath << std::endl;
            }
            exit(success ? 0 : 1);
        } else if (pid < 0) {
            std::cerr << "Fork failed for " << filepath << std::endl;
        }
    }

    // Wait for all child processes
    for (size_t i = 0; i < filepaths.size(); ++i) {
        int status;
        wait(&status);
    }

    std::cout << "All operations completed." << std::endl;
    return 0;
}