#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

// Structure to represent an event in the log
struct Event {
    long timestamp;
    std::string token;
    std::string name;
    bool isEmployee;
    bool isArrival;
    int roomId;
    // Constructor for Event
    Event(long t, const std::string& tok, const std::string& n, bool emp, bool arr, int room = -1)
        : timestamp(t), token(tok), name(n), isEmployee(emp), isArrival(arr), roomId(room) {}
};

// Main class for reading and processing the log

class LogReader {
private:
    std::string logFile;
    std::string token;
    std::vector<Event> events;
    std::map<std::string, bool> inCampus;
    std::map<std::string, int> currentRoom;
    std::map<std::string, std::vector<int>> roomHistory;
    std::map<std::string, long> totalTime;
    std::map<std::string, long> lastEntry;
    
    unsigned char key[32];
    unsigned char salt[16];
    unsigned char iv[12];   // IV for AES-GCM

    // Structure to represent a time range
    struct TimeRange {
    long start;
    long end;
    TimeRange(long s, long e) : start(s), end(e) {}
};
// Structure to represent room occupancy
struct RoomOccupancy {
    std::map<std::string, std::vector<TimeRange>> occupants;
};
// Derive the encryption key from the token
void deriveKey() {
    
    
    PKCS5_PBKDF2_HMAC(token.c_str(), token.length(), salt, 16, 200000, EVP_sha256(), 32, key);

  
}
        // Read and decrypt the log file
        bool readAndDecryptLog() {
            std::ifstream file(logFile, std::ios::binary);
            if (!file) {
                std::cerr << "Error: Unable to open file" << std::endl;
                return false;
            }
            // Read the salt and derive the key
            file.read(reinterpret_cast<char*>(salt), sizeof(salt));
            
        
            deriveKey();

            // Read and verify the file header
            char magic[8];
            uint32_t version;
            file.read(magic, 8);
            file.read(reinterpret_cast<char*>(&version), sizeof(version));
            
            file.read(reinterpret_cast<char*>(iv), sizeof(iv));

            if (!file) {
                std::cerr << "Error: File header read failed" << std::endl;
                return false;
            }

            // Verify magic number
            if (std::string(magic, 8) != "SECURLOG") {
                std::cerr << "Error: Invalid magic number" << std::endl;
                return false;
            }

            

            // Read the encrypted content
            std::vector<unsigned char> encrypted_content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

           



            if (encrypted_content.size() < 16) {
                std::cerr << "Error: Encrypted content too short" << std::endl;
                return false;
            }

            // Extract the authentication tag
            unsigned char tag[16];
            std::copy(encrypted_content.end() - 16, encrypted_content.end(), tag);
            encrypted_content.resize(encrypted_content.size() - 16);

            
            // Set up the decryption context
            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!ctx) {
                std::cerr << "Error: Unable to create cipher context" << std::endl;
                return false;
            }
            // Initialize the decryption
            if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
                std::cerr << "Error: Decryption initialization failed" << std::endl;
                EVP_CIPHER_CTX_free(ctx);
                return false;
            }

            // Decrypt the content
            std::vector<unsigned char> decrypted_content(encrypted_content.size());
            int len;
            if (EVP_DecryptUpdate(ctx, decrypted_content.data(), &len, encrypted_content.data(), encrypted_content.size()) != 1) {
                std::cerr << "Error: Decryption update failed" << std::endl;
                EVP_CIPHER_CTX_free(ctx);
                return false;
            }
            int plaintext_len = len;

            // Set the expected tag value
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag) != 1) {
                std::cerr << "Error: Setting GCM tag failed" << std::endl;
                EVP_CIPHER_CTX_free(ctx);
                return false;
            }

            // Finalize the decryption
            int ret = EVP_DecryptFinal_ex(ctx, decrypted_content.data() + len, &len);
            if (ret <= 0) {
                std::cerr << "Error: Decryption failed or integrity check failed" << std::endl;
                EVP_CIPHER_CTX_free(ctx);
                return false;
            }

            plaintext_len += len;
            decrypted_content.resize(plaintext_len);

            EVP_CIPHER_CTX_free(ctx);

            

            // Parse the decrypted content
            std::string decrypted_str(decrypted_content.begin(), decrypted_content.end());
            std::istringstream iss(decrypted_str);
            std::string line;
            while (std::getline(iss, line)) {
                Event event(0, "", "", false, false);
                std::istringstream line_iss(line);
                line_iss >> event.timestamp >> event.token >> event.name >> event.isEmployee >> event.isArrival >> event.roomId;
                if (event.token != token) {
                    std::cerr << "Error: Token mismatch in log entry" << std::endl;
                    return false;
                }
                events.push_back(event);
                updateState(event);
            }
            return true;
        }
    bool readLog() {
        std::ifstream file(logFile);
        if (!file) return false;

        Event event(0, "", "", false, false);
        while (file >> event.timestamp >> event.token >> event.name >> event.isEmployee >> event.isArrival >> event.roomId) {
            if (event.token != token) {
                std::cout << "integrity violation" << std::endl;
                exit(255);
            }
            events.push_back(event);
            updateState(event);
        }
        return true;
    }
    // Update the state based on an event
    void updateState(const Event& event) {
            std::string key = (event.isEmployee ? "E:" : "G:") + event.name;
            if (event.isArrival) {
                if (event.roomId == -1) {
                    inCampus[key] = true;
                    lastEntry[key] = event.timestamp;
                } else {
                    currentRoom[key] = event.roomId;
                    // Only add to room history when entering a room
                    if (roomHistory[key].empty() || roomHistory[key].back() != event.roomId) {
                        roomHistory[key].push_back(event.roomId);
                    }
                }
            } else {
                if (event.roomId == -1) {
                    inCampus[key] = false;
                    totalTime[key] += event.timestamp - lastEntry[key];
                    currentRoom.erase(key);
                } else {
                    currentRoom.erase(key);
                }
            }
        }
    // Check if a name exists in the log
    bool nameExists(const std::string& name, bool isEmployee) const {
        std::string key = (isEmployee ? "E:" : "G:") + name;
        return inCampus.find(key) != inCampus.end() || totalTime.find(key) != totalTime.end();
    }

    // Helper function to sort a set of strings
    std::vector<std::string> sortedNames(const std::set<std::string>& names) const {
        std::vector<std::string> sorted(names.begin(), names.end());
        std::sort(sorted.begin(), sorted.end());
        return sorted;
    }
    // Print the current state of the campus
    void printCurrentState() {
        std::set<std::string> employees, guests;
        std::map<int, std::set<std::string>> rooms;

        for (const auto& pair : inCampus) {
            if (pair.second) {
                if (pair.first[0] == 'E') {
                    employees.insert(pair.first.substr(2));
                } else {
                    guests.insert(pair.first.substr(2));
                }
            }
        }

        for (const auto& pair : currentRoom) {
            rooms[pair.second].insert(pair.first.substr(2));
        }

        std::cout << join(sortedNames(employees), ",") << std::endl;
        std::cout << join(sortedNames(guests), ",") << std::endl;

        for (const auto& room : rooms) {
            std::cout << room.first << ": " << join(sortedNames(room.second), ",") << std::endl;
        }
    }
    // Print the room history for a specific person
    void printRoomHistory(const std::string& name, bool isEmployee) {
            if (!nameExists(name, isEmployee)) {
                return; // Print nothing if the name doesn't exist
            }

            std::string key = (isEmployee ? "E:" : "G:") + name;
            if (roomHistory.count(key) > 0) {
                const auto& rooms = roomHistory[key];
                if (!rooms.empty()) {
                    std::cout << rooms[0];
                    for (size_t i = 1; i < rooms.size(); ++i) {
                        std::cout << "," << rooms[i];
                    }
                    std::cout << std::endl;
                }
            }
        }
    // Print the total time spent on campus for a specific person
    void printTotalTime(const std::string& name, bool isEmployee) {
        if (!nameExists(name, isEmployee)) {
            return; // Print nothing if the name doesn't exist
        }

        std::string key = (isEmployee ? "E:" : "G:") + name;
        long time = totalTime[key];
        if (inCampus[key]) {
            time += events.back().timestamp - lastEntry[key];
        }
        if (time > 0) {
            std::cout << time << std::endl;
        }
    }

    // Print the rooms where all specified people were present at the same time
    void printIntersection(const std::vector<std::string>& names) {
        std::vector<std::string> existingNames;
        for (const auto& name : names) {
            if (nameExists(name.substr(2), name[0] == 'E')) {
                existingNames.push_back(name);
            }
        }

        if (existingNames.empty()) {
            return; // Print nothing if no specified names exist
        }

        std::map<int, RoomOccupancy> roomOccupancies;

        // Build room occupancy data
        for (const auto& event : events) {
            std::string key = (event.isEmployee ? "E:" : "G:") + event.name;
            if (event.roomId != -1) {
                auto& occupancy = roomOccupancies[event.roomId].occupants[key];
                if (event.isArrival) {
                    occupancy.push_back(TimeRange(event.timestamp, LONG_MAX));
                } else if (!occupancy.empty()) {
                    occupancy.back().end = event.timestamp;
                }
            }
        }

        std::set<int> commonRooms;
        for (const auto& room : roomOccupancies) {
            bool allPresent = true;
            for (const auto& name : names) {
                if (room.second.occupants.find(name) == room.second.occupants.end()) {
                    allPresent = false;
                    break;
                }
            }
            if (allPresent) {
                std::vector<TimeRange> intersectionRanges;
                if (room.second.occupants.find(names[0]) != room.second.occupants.end()) {
                    intersectionRanges = room.second.occupants.at(names[0]);
                }
                for (size_t i = 1; i < names.size(); ++i) {
                    std::vector<TimeRange> newIntersection;
                    if (room.second.occupants.find(names[i]) != room.second.occupants.end()) {
                        const auto& occupantRanges = room.second.occupants.at(names[i]);
                        size_t j = 0, k = 0;
                        while (j < intersectionRanges.size() && k < occupantRanges.size()) {
                            long start = std::max(intersectionRanges[j].start, occupantRanges[k].start);
                            long end = std::min(intersectionRanges[j].end, occupantRanges[k].end);
                            if (start < end) {
                                newIntersection.push_back(TimeRange(start, end));
                            }
                            if (intersectionRanges[j].end < occupantRanges[k].end) {
                                ++j;
                            } else {
                                ++k;
                            }
                        }
                        intersectionRanges = newIntersection;
                        if (intersectionRanges.empty()) {
                            allPresent = false;
                            break;
                        }
                    } else {
                        allPresent = false;
                        break;
                    }
                }
                if (allPresent && !intersectionRanges.empty()) {
                    commonRooms.insert(room.first);
                }
            }
        }

        if (!commonRooms.empty()) {
            std::vector<int> sortedRooms(commonRooms.begin(), commonRooms.end());
            std::sort(sortedRooms.begin(), sortedRooms.end());
            std::cout << join(sortedRooms, ",") << std::endl;
        }
    }
    // Helper function to join elements of a container into a string
    template<typename T>
    std::string join(const T& elements, const std::string& delimiter) {
        std::ostringstream os;
        auto it = elements.begin();
        if (it != elements.end()) {
            os << *it++;
        }
        while (it != elements.end()) {
            os << delimiter << *it++;
        }
        return os.str();
    }

public:
    // Constructor
    LogReader(const std::string& file, const std::string& tok) : logFile(file), token(tok) {
            
            
            if (!readAndDecryptLog()) {
                std::cout << "invalid" << std::endl;
                exit(255);
            }
        }

    // Process the command-line arguments and execute the appropriate query
    void processCommand(int argc, char* argv[]) {
        bool stateQuery = false, roomQuery = false, timeQuery = false, intersectionQuery = false;
        std::string queryName;
        bool queryIsEmployee = false;
        std::vector<std::string> intersectionNames;
        // Parse command-line arguments
        for (int i = 1; i < argc; ++i) {
            if (strcmp(argv[i], "-S") == 0) stateQuery = true;
            else if (strcmp(argv[i], "-R") == 0) roomQuery = true;
            else if (strcmp(argv[i], "-T") == 0) timeQuery = true;
            else if (strcmp(argv[i], "-I") == 0) intersectionQuery = true;
            else if (strcmp(argv[i], "-E") == 0) {
                if (roomQuery || timeQuery) {
                    queryName = argv[++i];
                    queryIsEmployee = true;
                } else if (intersectionQuery) {
                    intersectionNames.push_back("E:" + std::string(argv[++i]));
                }
            }
            else if (strcmp(argv[i], "-G") == 0) {
                if (roomQuery || timeQuery) {
                    queryName = argv[++i];
                    queryIsEmployee = false;
                } else if (intersectionQuery) {
                    intersectionNames.push_back("G:" + std::string(argv[++i]));
                }
            }
        }

        if (stateQuery) printCurrentState();
        else if (roomQuery) printRoomHistory(queryName, queryIsEmployee);
        else if (timeQuery) printTotalTime(queryName, queryIsEmployee);
        else if (intersectionQuery) {
            if (intersectionNames.empty()) {
                std::cout << "invalid" << std::endl;
                exit(255);
            } else {
                printIntersection(intersectionNames);
            }
        }
        else {
            std::cout << "invalid" << std::endl;
            exit(255);
        }
    }
};
// Main function: Handles command-line arguments and executes the appropriate action
int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cout << "invalid" << std::endl;
        return 255;
    }

    std::string token, logFile;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-K") == 0) token = argv[++i];
        else logFile = argv[i];
    }

    if (token.empty() || logFile.empty()) {
        std::cout << "invalid" << std::endl;
        return 255;
    }

    LogReader reader(logFile, token);
    reader.processCommand(argc, argv);

    return 0;
}