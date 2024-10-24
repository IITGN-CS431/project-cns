#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <map>
#include <cstring>
#include <cstdlib>
#include <cctype>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

const int MAX_TIMESTAMP = 1073741823;
const int MAX_ROOM_ID = 1073741823;

// Structure to represent an event in the log

struct Event {
    long timestamp;
    std::string token;
    std::string name;
    bool isEmployee;
    bool isArrival;
    int roomId;

    Event(long t, const std::string& tok, const std::string& n, bool emp, bool arr, int room = -1)
        : timestamp(t), token(tok), name(n), isEmployee(emp), isArrival(arr), roomId(room) {}
};
class SecureLogManager {
private:
    std::string logFile;
    std::string token;
    std::vector<Event> events;
    std::map<std::string, bool> inCampus;
    std::map<std::string, int> currentRoom;
    std::string validToken;

    // New members for encryption
    unsigned char key[32];

    unsigned char salt[16];
    unsigned char iv[12];   // IV for AES-GCM

    // Derives the encryption key from the token and salt
   void deriveKey() {
       
       PKCS5_PBKDF2_HMAC(token.c_str(), token.length(), salt, 16, 200000, EVP_sha256(), 32, key);
     
   }
    // Encrypts the log entries and writes them to the file
    bool encryptAndWriteLog() {
        std::string plaintext;
        for (const auto& event : events) {
            plaintext += std::to_string(event.timestamp) + " " + event.token + " " + event.name + " " +
                         std::to_string(event.isEmployee) + " " + std::to_string(event.isArrival) + " " +
                         std::to_string(event.roomId) + "\n";
        }

        

        // Generate a new IV for each write
        RAND_bytes(iv, sizeof(iv));

        
        // Set up the encryption context
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            std::cerr << "Error: Unable to create cipher context" << std::endl;
            return false;
        }

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
            std::cerr << "Error: Encryption initialization failed" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        // Encrypt the plaintext
        std::vector<unsigned char> ciphertext(plaintext.length() + EVP_MAX_BLOCK_LENGTH);
        int len;
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.length()) != 1) {
            std::cerr << "Error: Encryption update failed" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        int ciphertext_len = len;

        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
            std::cerr << "Error: Encryption finalization failed" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        ciphertext_len += len;

        // Get the tag
        unsigned char tag[16];
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
            std::cerr << "Error: Unable to get GCM tag" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        EVP_CIPHER_CTX_free(ctx);

        // Write the encrypted content to the file
        std::fstream file(logFile, std::ios::in | std::ios::out | std::ios::binary);
            if (!file) {
                std::cerr << "Error: Unable to open file for writing" << std::endl;
                return false;
            }

            // Skip the salt as it's already written
            file.seekp(sizeof(salt), std::ios::beg);

        // File structure: Magic Number (8 bytes) | Version (4 bytes) | Salt (16 bytes) | IV (12 bytes) | Encrypted Content | Tag (16 bytes)
        const char* magic = "SECURLOG";
        uint32_t version = 1;
        file.write(magic, 8);
        file.write(reinterpret_cast<const char*>(&version), sizeof(version));
        
        file.write(reinterpret_cast<const char*>(iv), sizeof(iv));
        file.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext_len);
        file.write(reinterpret_cast<const char*>(tag), sizeof(tag));
        
        if (!file) {
            std::cerr << "Error: Failed to write to file" << std::endl;
            return false;
        }
        

        file.close();

        

        return true;
    }
    // Reads and decrypts the log file
    bool readAndDecryptLog() {
            std::ifstream file(logFile, std::ios::binary);
            if (!file) {
                // If the file doesn't exist, initialize with empty data
                events.clear();
                inCampus.clear();
                currentRoom.clear();
                validToken = token;
                return true;
            }

            // Read the salt first
            file.read(reinterpret_cast<char*>(salt), sizeof(salt));
            deriveKey();

            char magic[8];
            uint32_t version;
            file.read(magic, 8);
            file.read(reinterpret_cast<char*>(&version), sizeof(version));
            file.read(reinterpret_cast<char*>(iv), sizeof(iv));

            // Read the rest of the file
            std::vector<unsigned char> encrypted_content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

            if (encrypted_content.size() < 16) return false;

            // The last 16 bytes are the tag
            unsigned char tag[16];
            std::copy(encrypted_content.end() - 16, encrypted_content.end(), tag);
            encrypted_content.resize(encrypted_content.size() - 16);

            // Set up the decryption context
            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);

            // Decrypt the content
            std::vector<unsigned char> decrypted_content(encrypted_content.size());
            int len;
            EVP_DecryptUpdate(ctx, decrypted_content.data(), &len, encrypted_content.data(), encrypted_content.size());
            int plaintext_len = len;

            // Set the expected tag value
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);

            // Finalize the decryption
            int ret = EVP_DecryptFinal_ex(ctx, decrypted_content.data() + len, &len);
            EVP_CIPHER_CTX_free(ctx);

            if (ret <= 0) {
                // Decryption failed - likely wrong token
                std::cout << "invalid" << std::endl;
                exit(255);
            }

            plaintext_len += len;
            decrypted_content.resize(plaintext_len);

            // Parse the decrypted content
            std::string decrypted_str(decrypted_content.begin(), decrypted_content.end());
            std::istringstream iss(decrypted_str);
            std::string line;
            events.clear();
            inCampus.clear();
            currentRoom.clear();

            // Read first event to establish valid token
            if (std::getline(iss, line)) {
                Event event(0, "", "", false, false);
                std::istringstream line_iss(line);
                line_iss >> event.timestamp >> event.token >> event.name >> event.isEmployee >> event.isArrival >> event.roomId;
                validToken = event.token;
                
                // Check if current token matches the file's token
                if (token != validToken) {
                    std::cout << "invalid" << std::endl;
                    exit(255);
                }
                
                events.push_back(event);
                updateState(event);
            }

            // Read remaining events
            while (std::getline(iss, line)) {
                Event event(0, "", "", false, false);
                std::istringstream line_iss(line);
                line_iss >> event.timestamp >> event.token >> event.name >> event.isEmployee >> event.isArrival >> event.roomId;
                events.push_back(event);
                updateState(event);
            }
            return true;
        }

    bool readLog() {
        std::ifstream file(logFile);
        if (!file) return true; // It's okay if the file doesn't exist yet

        Event event(0, "", "", false, false);
        while (file >> event.timestamp >> event.token >> event.name >> event.isEmployee >> event.isArrival >> event.roomId) {
            if (events.empty()) validToken = event.token;
            events.push_back(event);
            updateState(event);
        }
        return true;
    }
    // Updates the internal state based on an event
    void updateState(const Event& event) {
        std::string key = (event.isEmployee ? "E:" : "G:") + event.name;
        if (event.isArrival) {
            if (event.roomId == -1) {
                inCampus[key] = true;
            } else {
                currentRoom[key] = event.roomId;
            }
        } else {
            if (event.roomId == -1) {
                inCampus[key] = false;
                currentRoom.erase(key);
            } else {
                currentRoom.erase(key);
            }
        }
    }
    // Validates if a name contains only alphabetic characters
    bool isValidName(const std::string& name) {
        return !name.empty() && std::all_of(name.begin(), name.end(), [](char c) {
            return std::isalpha(c);
        });
    }

    // Validates if a token contains only alphanumeric characters

    bool isValidToken(const std::string& token) {
        return !token.empty() && std::all_of(token.begin(), token.end(), [](char c) {
            return std::isalnum(c);
        });
    }

    public:
        // Constructor: Initializes the SecureLogManager with a log file and token
        SecureLogManager(const std::string& file, const std::string& userToken) : logFile(file), token(userToken) {
            // Generate a random salt
            std::ifstream existingFile(logFile, std::ios::binary);
                if (existingFile) {
                    // File exists, read the salt
                    existingFile.read(reinterpret_cast<char*>(salt), sizeof(salt));
                    existingFile.close();
                    
                } else {
                    // New file, generate a new salt
                    RAND_bytes(salt, sizeof(salt));
                   
                }
                
                

                std::memset(iv, 0, sizeof(iv));
                
                deriveKey();
                
                if (!existingFile) {
                    // For a new file, we need to write the salt immediately
                    std::ofstream newFile(logFile, std::ios::binary);
                    if (newFile) {
                        newFile.write(reinterpret_cast<const char*>(salt), sizeof(salt));
                        newFile.close();
                    } 
                }
            
            if (!readAndDecryptLog()) {
                        // If reading fails, initialize with empty data
                        events.clear();
                        inCampus.clear();
                        currentRoom.clear();
                        validToken = token;

                        // Generate a new salt for future use
                        RAND_bytes(salt, sizeof(salt));
            }
            

        }
        // Appends a new entry to the log

        bool appendEntry(const Event& event) {
            if (!validateEntry(event)) return false;

            events.push_back(event);
            updateState(event);
            return encryptAndWriteLog();
        }

        // Validates an entry before appending it to the log

        bool validateEntry(const Event& event) {
            // Basic validation checks
            if (event.timestamp < 1 || event.timestamp > MAX_TIMESTAMP) return false;
            if (!events.empty() && event.timestamp <= events.back().timestamp) return false;
            if (!isValidToken(event.token)) return false;
            if (!validToken.empty() && event.token != validToken) return false;
            if (!isValidName(event.name)) return false;
            if (event.roomId < -1 || event.roomId > MAX_ROOM_ID) return false;

            std::string key = (event.isEmployee ? "E:" : "G:") + event.name;

            if (event.isArrival) {
                if (event.roomId == -1) {
                    // Entering campus
                    if (inCampus[key]) return false;
                } else {
                    // Entering room
                    if (!inCampus[key] || currentRoom.count(key) > 0) return false;
                }
            } else {
                if (event.roomId == -1) {
                    // Leaving campus - Must not be in any room
                    if (!inCampus[key] || currentRoom.count(key) > 0) return false;
                } else {
                    // Leaving room
                    if (currentRoom[key] != event.roomId) return false;
                }
            }

            return true;
        }
    };

    // Processes a batch file containing multiple log entries
    bool processBatchFile(const std::string& batchFile) {
        std::ifstream file(batchFile);
        if (!file) {
            std::cout << "invalid" << std::endl;
            return false;
        }

        std::string line;
        bool anySuccess = false;
        std::string defaultToken = "defaultToken";

        while (std::getline(file, line)) {
            std::istringstream iss(line);
            std::vector<std::string> args;
            std::string arg;
            while (iss >> arg) {
                args.push_back(arg);
            }

            long timestamp = 0;
            std::string token, name, logFile;
            bool isEmployee = false, isGuest = false;
            bool isArrival = false, isLeaving = false;
            int roomId = -1;
            bool hasName = false;

            for (size_t i = 0; i < args.size(); ++i) {
                if (args[i] == "-T") timestamp = std::stol(args[++i]);
                else if (args[i] == "-K") token = args[++i];
                else if (args[i] == "-E") {
                    if (isGuest) {
                        std::cout << "invalid" << std::endl;
                        continue;
                    }
                    name = args[++i];
                    isEmployee = true;
                    hasName = true;
                }
                else if (args[i] == "-G") {
                    if (isEmployee) {
                        std::cout << "invalid" << std::endl;
                        continue;
                    }
                    name = args[++i];
                    isGuest = true;
                    hasName = true;
                }
                else if (args[i] == "-A") {
                    if (isLeaving) {
                        std::cout << "invalid" << std::endl;
                        continue;
                    }
                    isArrival = true;
                }
                else if (args[i] == "-L") {
                    if (isArrival) {
                        std::cout << "invalid" << std::endl;
                        continue;
                    }
                    isLeaving = true;
                }
                else if (args[i] == "-R") roomId = std::stoi(args[++i]);
                else logFile = args[i];
            }

            // Additional validation
            if (logFile.empty() || token.empty() || !hasName || timestamp == 0 || (!isArrival && !isLeaving)) {
                std::cout << "invalid" << std::endl;
                continue;
            }

            SecureLogManager manager(logFile, token);
            Event event(timestamp, token, name, isEmployee, isArrival, roomId);
            if (!manager.appendEntry(event)) {
                std::cout << "invalid" << std::endl;
            } else {
                anySuccess = true;
            }
        }

        return anySuccess;
    }

// Main function: Handles command-line arguments and executes the appropriate action
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "invalid" << std::endl;
        return 255;
    }

    if (std::string(argv[1]) == "-B") {
        if (argc != 3) {
            std::cout << "invalid" << std::endl;
            return 255;
        }
        return processBatchFile(argv[2]) ? 0 : 255;
    }

    long timestamp = 0;
    std::string token, name, logFile;
    bool isEmployee = false, isGuest = false;
    bool isArrival = false, isLeaving = false;
    int roomId = -1;
    bool hasName = false;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-T") == 0) timestamp = std::stol(argv[++i]);
        else if (strcmp(argv[i], "-K") == 0) token = argv[++i];
        else if (strcmp(argv[i], "-E") == 0) { 
            if (isGuest) {
                std::cout << "invalid" << std::endl;
                return 255;
            }
            name = argv[++i]; 
            isEmployee = true;
            hasName = true;
        }
        else if (strcmp(argv[i], "-G") == 0) { 
            if (isEmployee) {
                std::cout << "invalid" << std::endl;
                return 255;
            }
            name = argv[++i]; 
            isGuest = true;
            hasName = true;
        }
        else if (strcmp(argv[i], "-A") == 0) {
            if (isLeaving) {
                std::cout << "invalid" << std::endl;
                return 255;
            }
            isArrival = true;
        }
        else if (strcmp(argv[i], "-L") == 0) {
            if (isArrival) {
                std::cout << "invalid" << std::endl;
                return 255;
            }
            isLeaving = true;
        }
        else if (strcmp(argv[i], "-R") == 0) roomId = std::stoi(argv[++i]);
        else logFile = argv[i];
    }

    // Additional validation
    if (logFile.empty() || token.empty() || !hasName || timestamp == 0 || (!isArrival && !isLeaving)) {
        std::cout << "invalid" << std::endl;
        return 255;
    }

    SecureLogManager manager(logFile, token);
    Event event(timestamp, token, name, isEmployee, isArrival, roomId);
    if (!manager.appendEntry(event)) {
        std::cout << "invalid" << std::endl;
        return 255;
    }

    return 0;
}