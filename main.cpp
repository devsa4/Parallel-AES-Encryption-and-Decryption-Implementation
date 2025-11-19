#include <iostream>
#include <string>
#include <vector>
#include <sys/wait.h>
#include <unistd.h>
#include "encryptor.h"
#include "decryptor.h"
using namespace std;
int main() {
    int choice;
    int num_threads = 4;
    string passphrase;
    vector<string> filepaths;
    cout << "Choose operation:\n1. Encrypt\n2. Decrypt\n> ";
    cin >> choice;
    cin.ignore();
    cout << "Enter passphrase: ";
    getline(cin, passphrase);
    cout << "Enter number of threads (default 4): ";
    cin >> num_threads;
    cin.ignore();
    if (num_threads <= 0) num_threads = 4;
    cout << "Enter file paths (comma-separated): ";
    string input;
    getline(cin, input);
    size_t pos = 0;
    while ((pos = input.find(',')) != string::npos) {
        filepaths.push_back(input.substr(0, pos));
        input.erase(0, pos + 1);
    }
    if (!input.empty()) filepaths.push_back(input);
    for (const auto& filepath : filepaths) {
        pid_t pid = fork();
        if (pid == 0) {
            string outpath;
            bool success = false;
            if (choice == 1) {
                outpath = filepath + ".enc";
                success = encrypt_file_multithreaded(filepath, outpath, passphrase, num_threads);
            } else if (choice == 2) {
                outpath = filepath + ".dec";
                success = decrypt_file_multithreaded(filepath, outpath, passphrase, num_threads);
            } else {
                cerr << "Invalid choice!" << endl;
                exit(1);
            }
            if (success) cout << "Success -> " << outpath << endl;
            else cerr << "Failed -> " << filepath << endl;
            exit(success ? 0 : 1);
        } else if (pid < 0) {
            cerr << "Fork failed for " << filepath << endl;
        }
    }
    for (size_t i = 0; i < filepaths.size(); ++i) {
        int status;
        wait(&status);
    }
    cout << "All operations completed." << endl;
    return 0;
}