#include <iostream>
 #include <string>
 
 int main() {
 std::string filepath;
 std::string key;
 int choice;
 
 // Ask for file path
 std::cout << "Enter the path of the file: ";
 std::getline(std::cin, filepath);
 
 // Ask for secret key
 std::cout << "Enter the secret key: ";
 std::getline(std::cin, key);
 
 // Ask for operation
 std::cout << "Choose operation:\n1. Encrypt\n2. Decrypt\nEnter choice (1 or 2): ";
 std::cin >> choice;
 
 // Confirm input
 std::cout << "\nFile: " << filepath << "\nKey: " << key << "\nOperation: " << (choice == 1 ? "Encrypt" : "Decrypt") << "\n";
 
 // You can now pass these values to your encryption/decryption functions
 return 0;
 }