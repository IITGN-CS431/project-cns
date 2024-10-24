#include <iostream>
#include <fstream>
#include <string>
#include <sstream>       // For parsing the log entry
#include "parseAppend.h" // Include the input parsing module
#include <unordered_map>
#include <map>
#include "security.h" // Include the security file
#include <cstring>
#include <cstdlib>
#include <sys/stat.h>
#include <vector>
using namespace std;

// Struct to store the parsed data of the last activity
struct Activity
{
    int T = -1;          // Timestamp
    string K = "";       // Employee key (name or ID)
    string E = "";       // Role or other identifier
    string G = "";       // Department or other identifier
    int R = -1;          // Additional field
    bool A_flag = false; // Activity flag
    bool L_flag = false; // Log flag
};

// Function to append ".log" if it's not already there
string ensure_log_extension(const char *logFileName)
{
    string logName(logFileName); // Convert the char* to a string for easier manipulation
    if (logName.size() < 4 || logName.substr(logName.size() - 4) != ".txt")
    {
        logName += ".txt"; // Add ".log" if not already present
    }
    return logName;
}

int read_last_timestamp(char *decryptedDataChar)
{
    // Convert the decryptedDataChar (const char*) to std::string for easier manipulation
    // cout << decryptedDataChar << endl;
    std::string decryptedData(decryptedDataChar);

    // If the decrypted log data is empty, return 0 as the last timestamp
    if (decryptedData.empty())
    {
        return 0;
    }

    // Split the decrypted data into lines
    std::istringstream iss(decryptedData);
    std::string line;
    std::string lastLine;

    // Traverse through the decrypted data line by line to find the last non-empty line
    while (std::getline(iss, line))
    {
        if (!line.empty())
        {
            lastLine = line; // Update lastLine to the most recent non-empty line
        }
    }

    // If no valid lines are found, return 0
    if (lastLine.empty())
    {
        return 0;
    }

    // Extract the timestamp from the last line
    int lastTimestamp = 0;
    std::stringstream ss(lastLine);
    std::string temp;

    // Assuming the timestamp is the second token in the line
    ss >> temp >> lastTimestamp;

    return lastTimestamp;
}

// Function to parse a log entry into the LastActivity struct
Activity parse_log_entry(const string &logEntry)
{
    Activity activity;
    stringstream ss(logEntry);
    string temp;

    // Parse the general fields
    ss >> temp >> activity.T   // "T:"
        >> temp >> activity.K  // "K:"
        >> temp >> activity.E  // "E:"
        >> temp >> activity.G  // "G:"
        >> temp >> activity.R; // "R:"

    // Parse "A_flag:" and "L_flag:" properly
    ss >> temp; // "A_flag:"
    if (temp == "A_flag:")
    {
        string aFlagValue;
        ss >> aFlagValue;
        activity.A_flag = (aFlagValue == "true");
    }

    ss >> temp; // "L_flag:"
    if (temp == "L_flag:")
    {
        string lFlagValue;
        ss >> lFlagValue;
        activity.L_flag = (lFlagValue == "true");
    }

    return activity;
}

Activity givelastActivity(char *decryptedText, ParsedData data)
{
    // Determine the person name (from E or G)
    std::string personName;
    if (data.E != nullptr)
    {
        personName = data.E;
    }
    else if (data.G != nullptr)
    {
        personName = data.G;
    }

    Activity lastActivity;
    // cout << "dec passed: " << endl
    //      << decryptedText << endl;
    char *entryStart = decryptedText;
    // cout << "entry start: " << endl
    //      << entryStart << endl;
    // Traverse the log entries from the last entry to the first
    for (char *current = entryStart; *current != '\0'; current++)
    {
        if (*current == '\0')
        {
            // Process the log entry between entryStart and current
            std::string logEntry(entryStart);
            Activity activity = parse_log_entry(logEntry);

            // Check if the activity matches the person name (Employee or Guest)
            if ((activity.E != "" && data.E != nullptr && activity.E == personName) ||
                (activity.G != "" && data.G != nullptr && activity.G == personName))
            {
                lastActivity = activity;
            }

            entryStart = current + 1; // Move to the next entry
        }
    }

    return lastActivity;
}

bool checks_on_sequence(Activity lastActivity, ParsedData data)
{
    // no last activity, now entry on campus
    if (!lastActivity.A_flag && !lastActivity.L_flag && data.A_flag && data.R == -1)
    {
        return true;
    }
    if (lastActivity.L_flag && lastActivity.R != -1 && data.A_flag && data.R != -1)
    {
        return true;
    }
    // previous activity
    // previous is campus arrival, now new entry is arrival in room
    if (lastActivity.A_flag && lastActivity.R == -1 && data.A_flag && data.R != -1)
    {
        return true;
    }
    // previous is room entry, current is room exit
    else if (lastActivity.A_flag && lastActivity.R != -1 && data.L_flag && data.R != -1 && lastActivity.R == data.R)
    {
        return true;
    }
    // previous is room exit, current is campus departure
    else if (lastActivity.L_flag && lastActivity.R != -1 && data.L_flag && data.R == -1)
    {
        return true;
    }
    // previous is room exit, now going into new room
    else if (lastActivity.L_flag && lastActivity.R != -1 && data.A_flag && data.R != -1)
    {
        return true;
    }
    // no entry in the room, direct campus entry and departure
    else if (lastActivity.A_flag && lastActivity.R == -1 && data.L_flag && data.R == -1)
    {
        return true;
    }
    else
    {
        return false;
    }
}

const char *combineStrings(const char *first, long long firstLength, const char *second)
{
    // Calculate the total length of the combined string (+2 for the newline and null terminator)
    size_t secondLength = std::strlen(second);
    size_t totalLength = firstLength + secondLength + 2; // +2 for '\n' and '\0'

    // Allocate memory for the combined string
    char *combined = new char[totalLength];
    // cout << "just first string " << first << endl;

    // Copy the first string into the combined string (up to firstLength characters)
    size_t i = 0;
    // std::cout << "\nFirst string goes here: \n";
    for (; i < firstLength; ++i)
    {
        combined[i] = first[i];
        // std::cout << combined[i]; // Debugging: Print each character
    }
    // std::cout << std::endl;

    // Add a newline after the first string
    combined[i] = '\n';
    ++i;

    // std::cout << "Second string goes here: \n";
    // Copy the second string into the combined string after the newline
    for (size_t j = 0; j < secondLength; ++j, ++i)
    {
        combined[i] = second[j];
        // std::cout << combined[i]; // Debugging: Print each character
    }
    // std::cout << std::endl;

    // Null-terminate the combined string
    combined[i] = '\0';

    // Return the combined string
    return combined;
}

const char *convertParsedDataToCStr(const ParsedData &data)
{
    // Allocate a sufficiently large buffer to hold the final string
    // Adjust this size based on the expected maximum size of the formatted string
    char *buffer = new char[512]; // Dynamic memory allocation for a 512-byte buffer
    std::memset(buffer, 0, 512);  // Initialize the buffer with zeros

    // Start constructing the formatted string
    std::ostringstream oss;

    // Add each part, including default/null values
    oss << "T: " << (data.T != -1 ? std::to_string(data.T) : "null") << " "
        << "K: " << (data.K ? data.K : "null") << " "
        << "E: " << (data.E ? data.E : "null") << " "
        << "G: " << (data.G ? data.G : "null") << " "
        << "R: " << (data.R != -1 ? std::to_string(data.R) : "-1") << " "
        << "A_flag: " << (data.A_flag ? "true" : "false") << " "
        << "L_flag: " << (data.L_flag ? "true" : "false");

    // Copy the formatted string into the buffer
    std::strncpy(buffer, oss.str().c_str(), 511); // Copy to buffer, limit to 511 chars
    buffer[511] = '\0';                           // Ensure null termination

    // Return the final C-style string
    return buffer;
}

int main(int argc, char *argv[])
{
    // Call the input parsing function (not implemented in this snippet)
    ParsedData data;
    bool batchMode = false; // Flag to check if we're in batch mode
    string batchFileName;

    // Check if the -B flag is provided
    for (int i = 1; i < argc; ++i)
    {
        if (string(argv[i]) == "-B" && i + 1 < argc)
        {
            batchMode = true;
            batchFileName = argv[++i];
            break;
        }
    }

    if (batchMode)
    {
        // Open the batch file
        // cout<<"yes got it"<<endl ;
        ifstream batchFile(batchFileName);
        if (!batchFile.is_open())
        {
            // cerr << "Error: Could not open batch file." << endl;
            cout << "invalid" << endl;
            exit(255);
        }

        string line;
        int lineNumber = 0;

        // Process each line in the batch file
        while (getline(batchFile, line))
        {
            ++lineNumber;
            // Parse the line as input
            char *lineArgs[100]; // Arbitrary large array to hold arguments
            int argCount = 0;

            // Split the line into arguments (this function needs to be implemented)
            istringstream iss(line);
            string token1;
            const char *logFilePath = "random/path/";
            lineArgs[argCount++] = strdup(logFilePath);
            while (iss >> token1)
            {
                lineArgs[argCount++] = strdup(token1.c_str());
            }

            // cout<<*lineArgs<<endl ;
            //  cout << "Line " << lineNumber << ": Number of arguments (argc): " << argCount << endl;

            // // Also, print the arguments if needed for further debugging
            // for (int i = 0; i < argCount; ++i) {
            //     cout << "Arg[" << i << "]: " << lineArgs[i] << endl;
            // }

            // cout<<line<<endl ;
            //  Call parse_input to get ParsedData for the current line
            data = parse_input(argCount, lineArgs);
            if (sodium_init() < 0)
            {
                // cerr << "Failed to initialize sodium" << endl;
                invalid_batch("");
            }

            SecureLogger logger;
            const char *token = data.K;

            const char *to_be_encrypted_New = convertParsedDataToCStr(data);
            const unsigned char *plaintextNew = reinterpret_cast<const unsigned char *>(to_be_encrypted_New);
            // cout << "plaintext size: " << strlen((const char *)plaintext) << endl;
            string filename = data.log;
            filename += ".txt";

            int status = logger.init(token, filename);

            if (status == 0)
            {
                // cout << "The logfile exists from before and the token is correct" << endl;
                // std::cout << "Parsed Data:" << std::endl;
                // std::cout << "A_flag: " << (data.A_flag ? "true" : "false") << std::endl;
                // std::cout << "L_flag: " << (data.L_flag ? "true" : "false") << std::endl;
                // std::cout << "T: " << data.T << std::endl;
                // std::cout << "K: " << (data.K ? data.K : "nullptr") << std::endl;
                // std::cout << "E: " << (data.E ? data.E : "nullptr") << std::endl;
                // std::cout << "G: " << (data.G ? data.G : "nullptr") << std::endl;
                // std::cout << "R: " << data.R << std::endl;
                // std::cout << "log: " << (data.log ? data.log : "nullptr") << std::endl;
                char *decryptedDataChar;
                try
                {
                    // cout << "Decrypting file....." << endl;

                    unsigned char *decryptedData = logger.decrypt_log();
                    decryptedDataChar = reinterpret_cast<char *>(decryptedData);
                    // cout << "Decrypted Data first: " << decryptedDataChar << endl;
                    unsigned long long leng1 = logger.get_plaintext_len();
                    char newarray1[leng1];
                    for (unsigned long long i = 0; i < leng1; i++)
                    {
                        newarray1[i] = decryptedDataChar[i];
                    }
                    // cout << "decrypted size: " << strlen((char *)data) << endl;
                    // cout << "Decryption of file successful" << endl;
                    // const char *decryptedDataChar1 = strdup(decryptedDataChar);  // Duplicate string to avoid modification
                    // cout<<" decrypt1 "<<decryptedDataChar1<<endl ;

                    // Determine the person name (from E or G)
                    std::string personName;
                    if (data.E != nullptr)
                    {
                        personName = data.E;
                    }
                    else if (data.G != nullptr)
                    {
                        personName = data.G;
                    }

                    Activity lastactivity;

                    // Convert decrypted_data to a string for easier line-by-line processing
                    string decryptedString(reinterpret_cast<const char *>(newarray1));

                    // Now we'll process the decrypted string line by line using a stringstream
                    stringstream logStream(decryptedString);
                    string line1;

                    while (getline(logStream, line1))
                    {
                        stringstream ss(line1);
                        // T: 1 K: token1 E: Fred G: null R: -1 A_flag: true L_flag: false
                        string T, timestamp, K, token, E, employee, G, guest, R, roomId, A, a_flag_str, L, l_flag_str;
                        bool A_flag, L_flag;
                        // Extract the fields from the log line
                        ss >> T >> timestamp >> K >> token >> E >> employee >> G >> guest >> R >> roomId >> A >> a_flag_str >> L >> l_flag_str;
                        // Convert A_flag and L_flag from string to boolean
                        if (employee == personName || guest == personName)
                        {
                            A_flag = (a_flag_str == "true");
                            // L_flag = (l_flag_str == "true");
                            L_flag = !A_flag;
                            // cout << "time: " << timestamp << endl;
                            // cout << "room: " << roomId << endl;
                            lastactivity.T = stoi(timestamp);
                            lastactivity.K = token;
                            lastactivity.E = employee;
                            lastactivity.G = guest;
                            lastactivity.R = stoi(roomId);
                            lastactivity.A_flag = A_flag;
                            lastactivity.L_flag = L_flag;
                        }
                    }

                    // // Activity lastactivity = givelastActivity(decryptedDataChar, data);
                    // cout << "lastactivity" << endl;
                    // cout << "last act time: " << lastactivity.T << endl;
                    // cout << "last act token: " << lastactivity.K << endl;
                    // cout << "last act E name: " << lastactivity.E << endl;
                    // cout << "last act G name: " << lastactivity.G << endl;
                    // cout << "last act R: " << lastactivity.R << endl;
                    // cout << "last act A: " << lastactivity.A_flag << endl;
                    // cout << "last act L: " << lastactivity.L_flag << endl;
                    unsigned char *decryptedData1 = logger.decrypt_log();
                    char *decryptedDataChar1 = reinterpret_cast<char *>(decryptedData1);
                    // cout << "Decrypted Data just after: " << decryptedDataChar1 << endl;
                    unsigned long long leng = logger.get_plaintext_len();
                    char newarray[leng];
                    for (unsigned long long i = 0; i < leng; i++)
                    {
                        newarray[i] = decryptedDataChar1[i];
                    }
                    // cout << "in main" << endl
                    //      << decryptedDataChar1 << endl;
                    ///////////////////////////////////////
                    // Open a file in write mode
                    // std::ofstream outfile("debug.txt");
                    // // Check if file opened successfully
                    // if (outfile.is_open())
                    // {
                    //     // Write the unsigned char* data into the file
                    //     outfile << "parnajl\n";
                    //     // outfile << decryptedDataChar1;
                    //     outfile << newarray;

                    //     // Close the file after writing
                    //     outfile.close();

                    //     std::cout << "Data written to debug.txt successfully." << std::endl;
                    // }
                    // else
                    // {
                    //     std::cerr << "Error opening file debug.txt" << std::endl;
                    // }
                    // //////////////////////////////////////////
                    // int lastTimestamp = read_last_timestamp(decryptedDataChar1);

                    // std::string decryptedDataS = string(newarray);
                    string decryptedDataS(reinterpret_cast<const char *>(newarray));
                    // cout << "decrypted data string:" << endl
                    //      << decryptedDataS << endl;

                    // If the decrypted log data is empty, return 0 as the last timestamp
                    if (decryptedDataS.empty())
                    {
                        invalid_batch("");
                        // cout << "invalid" << endl;
                        // return 255;
                    }

                    // Split the decrypted data into lines
                    std::istringstream iss(decryptedDataS);
                    std::string line;
                    std::string lastLine;

                    // Traverse through the decrypted data line by line to find the last non-empty line
                    while (std::getline(iss, line))
                    {
                        if (!line.empty())
                        {
                            lastLine = line; // Update lastLine to the most recent non-empty line
                        }
                    }

                    // If no valid lines are found, return 0
                    if (lastLine.empty())
                    {
                        invalid_batch("");
                    }

                    // Extract the timestamp from the last line
                    int lastTimestamp = 0;
                    std::stringstream ss(lastLine);
                    std::string temp;

                    // Assuming the timestamp is the second token in the line
                    ss >> temp >> lastTimestamp;

                    // cout << lastTimestamp << " this is the timestamp" << endl;
                    // Ensure the provided timestamp is greater than the last one
                    if (data.T <= lastTimestamp)
                    {
                        // cerr << "Error: The provided timestamp T must be greater than the last used timestamp (" << lastTimestamp << ")" << endl;
                        invalid_batch("");
                    }

                    if (checks_on_sequence(lastactivity, data))
                    {
                        // here

                        // cout<<" decrypted data :"<<decryptedDataChar2<<endl ;
                        // cout<<" encrypted dta "<<to_be_encrypted_New<<endl ;

                        long long leng = logger.get_plaintext_len();

                        // const char* combinedLogFile = combineStrings(decryptedDataChar2, leng, to_be_encrypted_New) ;
                        size_t secondLength = std::strlen(to_be_encrypted_New);
                        size_t totalLength = leng + secondLength + 2; // +2 for '\n' and '\0'

                        // Allocate memory for the combined string
                        char *combined = new char[totalLength];
                        unsigned char *decryptedData2 = logger.decrypt_log();
                        char *decryptedDataChar2 = reinterpret_cast<char *>(decryptedData2);
                        // cout<<"just first string "<<decryptedDataChar2<<endl ;

                        // Copy the first string into the combined string (up to firstLength characters)
                        size_t i = 0;
                        for (; i < leng; ++i)
                        {
                            combined[i] = decryptedDataChar2[i];
                            // std::cout << combined[i];  // Debugging: Print each character
                        }
                        // std::cout << std::endl;

                        // Add a newline after the first string
                        combined[i] = '\n';
                        ++i;

                        // Copy the second string into the combined string after the newline
                        for (size_t j = 0; j < secondLength; ++j, ++i)
                        {
                            combined[i] = to_be_encrypted_New[j];
                            // std::cout << combined[i];  // Debugging: Print each character
                        }

                        // Null-terminate the combined string
                        combined[i] = '\0';
                        // cout << "combined stirng final" << endl
                        //      << combined << endl;

                        // cout<<" combined log file : "<<combinedLogFile<<endl ;
                        try
                        {
                            // cout << "Encrypting plaintext....." << endl;
                            const unsigned char *combinedPlaintextNew = reinterpret_cast<const unsigned char *>(combined);
                            logger.encrypt_log_plaintext(combinedPlaintextNew);
                            // cout << "Encryption of plaintext successful" << endl;
                        }
                        catch (const runtime_error &e)
                        {
                            // cerr << "Encryption of plaintext error: " << e.what() << endl;
                            invalid_batch("");
                        }
                    }
                    else
                    {
                        invalid_batch("");
                    }
                }
                catch (const runtime_error &e)
                {
                    // cerr << "Decryption of file error: " << e.what() << endl;
                    // return 1; // Return an error code
                    invalid_batch("");
                }
            }
            else if (status == 2)
            {
                // cout << "The file does not exist from before" << endl;
                // printParsedData(data) ;
                //  std::cout << "Parsed Data:" << std::endl;
                //  std::cout << "A_flag: " << (data.A_flag ? "true" : "false") << std::endl;
                //  std::cout << "L_flag: " << (data.L_flag ? "true" : "false") << std::endl;
                //  std::cout << "T: " << data.T << std::endl;
                //  std::cout << "K: " << (data.K ? data.K : "nullptr") << std::endl;
                //  std::cout << "E: " << (data.E ? data.E : "nullptr") << std::endl;
                //  std::cout << "G: " << (data.G ? data.G : "nullptr") << std::endl;
                //  std::cout << "R: " << data.R << std::endl;
                //  std::cout << "log: " << (data.log ? data.log : "nullptr") << std::endl;
                if (data.A_flag && data.R == -1)
                {
                    try
                    {
                        // cout << "Encrypting plaintext....." << endl;
                        logger.encrypt_log_plaintext(plaintextNew);
                        // cout << "Encryption of plaintext successful" << endl;
                    }
                    catch (const runtime_error &e)
                    {
                        // cerr << "Encryption of plaintext error: " << e.what() << endl;
                        // return 1; // Return an error code
                        invalid_batch("");
                    }
                }
                else
                {
                    invalid_batch("");
                }
            }
            else if (status == -1)
            {
                // cout << "Token not verfified for file: " << filename << endl;
                invalid_batch("");
            }
            else
            {
                // cout << "Some error occured during the verification" << endl;
                invalid_batch("");
            }
        }

        batchFile.close();
    }
    else
    {
        data = parse_input(argc, argv);
        // Ensure the log file has the ".log" extension
        // string logFileName = ensure_log_extension(data.log);
        // Read the last used timestamp
        if (sodium_init() < 0)
        {
            // cerr << "Failed to initialize sodium" << endl;
            // return 1;
            invalid("");
        }

        SecureLogger logger;
        const char *token = data.K;

        const char *to_be_encrypted_New = convertParsedDataToCStr(data);
        const unsigned char *plaintextNew = reinterpret_cast<const unsigned char *>(to_be_encrypted_New);
        // cout << "plaintext size: " << strlen((const char *)plaintext) << endl;
        string filename = data.log;
        filename += ".txt";

        int status = logger.init(token, filename);

        if (status == 0)
        {
            // cout << "The logfile exists from before and the token is correct" << endl;
            // std::cout << "Parsed Data:" << std::endl;
            // std::cout << "A_flag: " << (data.A_flag ? "true" : "false") << std::endl;
            // std::cout << "L_flag: " << (data.L_flag ? "true" : "false") << std::endl;
            // std::cout << "T: " << data.T << std::endl;
            // std::cout << "K: " << (data.K ? data.K : "nullptr") << std::endl;
            // std::cout << "E: " << (data.E ? data.E : "nullptr") << std::endl;
            // std::cout << "G: " << (data.G ? data.G : "nullptr") << std::endl;
            // std::cout << "R: " << data.R << std::endl;
            // std::cout << "log: " << (data.log ? data.log : "nullptr") << std::endl;
            char *decryptedDataChar;
            try
            {
                // cout << "Decrypting file....." << endl;

                unsigned char *decryptedData = logger.decrypt_log();
                decryptedDataChar = reinterpret_cast<char *>(decryptedData);
                // cout << "Decrypted Data first: " << decryptedDataChar << endl;
                unsigned long long leng1 = logger.get_plaintext_len();
                char newarray1[leng1];
                for (unsigned long long i = 0; i < leng1; i++)
                {
                    newarray1[i] = decryptedDataChar[i];
                }
                // cout << "decrypted size: " << strlen((char *)data) << endl;
                // cout << "Decryption of file successful" << endl;
                // const char *decryptedDataChar1 = strdup(decryptedDataChar);  // Duplicate string to avoid modification
                // cout<<" decrypt1 "<<decryptedDataChar1<<endl ;

                // Determine the person name (from E or G)
                std::string personName;
                if (data.E != nullptr)
                {
                    personName = data.E;
                }
                else if (data.G != nullptr)
                {
                    personName = data.G;
                }

                Activity lastactivity;

                // Convert decrypted_data to a string for easier line-by-line processing
                string decryptedString(reinterpret_cast<const char *>(newarray1));

                // Now we'll process the decrypted string line by line using a stringstream
                stringstream logStream(decryptedString);
                string line1;

                while (getline(logStream, line1))
                {
                    stringstream ss(line1);
                    // T: 1 K: token1 E: Fred G: null R: -1 A_flag: true L_flag: false
                    string T, timestamp, K, token, E, employee, G, guest, R, roomId, A, a_flag_str, L, l_flag_str;
                    bool A_flag, L_flag;
                    // Extract the fields from the log line
                    ss >> T >> timestamp >> K >> token >> E >> employee >> G >> guest >> R >> roomId >> A >> a_flag_str >> L >> l_flag_str;
                    // Convert A_flag and L_flag from string to boolean
                    if (employee == personName || guest == personName)
                    {
                        A_flag = (a_flag_str == "true");
                        // L_flag = (l_flag_str == "true");
                        L_flag = !A_flag;
                        // cout << "time: " << timestamp << endl;
                        // cout << "room: " << roomId << endl;
                        lastactivity.T = stoi(timestamp);
                        lastactivity.K = token;
                        lastactivity.E = employee;
                        lastactivity.G = guest;
                        lastactivity.R = stoi(roomId);
                        lastactivity.A_flag = A_flag;
                        lastactivity.L_flag = L_flag;
                    }
                }

                // // Activity lastactivity = givelastActivity(decryptedDataChar, data);
                // cout << "lastactivity" << endl;
                // cout << "last act time: " << lastactivity.T << endl;
                // cout << "last act token: " << lastactivity.K << endl;
                // cout << "last act E name: " << lastactivity.E << endl;
                // cout << "last act G name: " << lastactivity.G << endl;
                // cout << "last act R: " << lastactivity.R << endl;
                // cout << "last act A: " << lastactivity.A_flag << endl;
                // cout << "last act L: " << lastactivity.L_flag << endl;
                unsigned char *decryptedData1 = logger.decrypt_log();
                char *decryptedDataChar1 = reinterpret_cast<char *>(decryptedData1);
                // cout << "Decrypted Data just after: " << decryptedDataChar1 << endl;
                unsigned long long leng = logger.get_plaintext_len();
                char newarray[leng];
                for (unsigned long long i = 0; i < leng; i++)
                {
                    newarray[i] = decryptedDataChar1[i];
                }
                // cout << "in main" << endl
                //      << decryptedDataChar1 << endl;
                ///////////////////////////////////////
                // Open a file in write mode
                // std::ofstream outfile("debug.txt");
                // // Check if file opened successfully
                // if (outfile.is_open())
                // {
                //     // Write the unsigned char* data into the file
                //     outfile << "parnajl\n";
                //     // outfile << decryptedDataChar1;
                //     outfile << newarray;

                //     // Close the file after writing
                //     outfile.close();

                //     std::cout << "Data written to debug.txt successfully." << std::endl;
                // }
                // else
                // {
                //     std::cerr << "Error opening file debug.txt" << std::endl;
                // }
                // //////////////////////////////////////////
                // int lastTimestamp = read_last_timestamp(decryptedDataChar1);

                // std::string decryptedDataS = string(newarray);
                string decryptedDataS(reinterpret_cast<const char *>(newarray));
                // cout << "decrypted data string:" << endl
                //      << decryptedDataS << endl;

                // If the decrypted log data is empty, return 0 as the last timestamp
                if (decryptedDataS.empty())
                {
                    invalid("");
                }

                // Split the decrypted data into lines
                std::istringstream iss(decryptedDataS);
                std::string line;
                std::string lastLine;

                // Traverse through the decrypted data line by line to find the last non-empty line
                while (std::getline(iss, line))
                {
                    if (!line.empty())
                    {
                        lastLine = line; // Update lastLine to the most recent non-empty line
                    }
                }

                // If no valid lines are found, return 0
                if (lastLine.empty())
                {
                    invalid("");
                }

                // Extract the timestamp from the last line
                int lastTimestamp = 0;
                std::stringstream ss(lastLine);
                std::string temp;

                // Assuming the timestamp is the second token in the line
                ss >> temp >> lastTimestamp;

                // cout << lastTimestamp << " this is the timestamp" << endl;
                // Ensure the provided timestamp is greater than the last one
                if (data.T <= lastTimestamp)
                {
                    // cerr << "Error: The provided timestamp T must be greater than the last used timestamp (" << lastTimestamp << ")" << endl;
                    // return 1;
                    invalid("");
                }

                if (checks_on_sequence(lastactivity, data))
                {
                    // here

                    // cout<<" decrypted data :"<<decryptedDataChar2<<endl ;
                    // cout<<" encrypted dta "<<to_be_encrypted_New<<endl ;

                    long long leng = logger.get_plaintext_len();

                    // const char* combinedLogFile = combineStrings(decryptedDataChar2, leng, to_be_encrypted_New) ;
                    size_t secondLength = std::strlen(to_be_encrypted_New);
                    size_t totalLength = leng + secondLength + 2; // +2 for '\n' and '\0'

                    // Allocate memory for the combined string
                    char *combined = new char[totalLength];
                    unsigned char *decryptedData2 = logger.decrypt_log();
                    char *decryptedDataChar2 = reinterpret_cast<char *>(decryptedData2);
                    // cout<<"just first string "<<decryptedDataChar2<<endl ;

                    // Copy the first string into the combined string (up to firstLength characters)
                    size_t i = 0;
                    for (; i < leng; ++i)
                    {
                        combined[i] = decryptedDataChar2[i];
                        // std::cout << combined[i];  // Debugging: Print each character
                    }
                    // std::cout << std::endl;

                    // Add a newline after the first string
                    combined[i] = '\n';
                    ++i;

                    // Copy the second string into the combined string after the newline
                    for (size_t j = 0; j < secondLength; ++j, ++i)
                    {
                        combined[i] = to_be_encrypted_New[j];
                        // std::cout << combined[i];  // Debugging: Print each character
                    }

                    // Null-terminate the combined string
                    combined[i] = '\0';
                    // cout << "combined stirng final" << endl
                    //      << combined << endl;

                    // cout<<" combined log file : "<<combinedLogFile<<endl ;
                    try
                    {
                        // cout << "Encrypting plaintext....." << endl;
                        const unsigned char *combinedPlaintextNew = reinterpret_cast<const unsigned char *>(combined);
                        logger.encrypt_log_plaintext(combinedPlaintextNew);
                        // cout << "Encryption of plaintext successful" << endl;
                    }
                    catch (const runtime_error &e)
                    {
                        // cerr << "Encryption of plaintext error: " << e.what() << endl;
                        // return 1; // Return an error code
                        invalid("");
                    }
                }
                else
                {
                    invalid("");
                }
            }
            catch (const runtime_error &e)
            {
                // cerr << "Decryption of file error: " << e.what() << endl;
                // return 1; // Return an error code
                invalid("");
            }
        }
        else if (status == 2)
        {
            // cout << "The file does not exist from before" << endl;
            // printParsedData(data) ;
            //  std::cout << "Parsed Data:" << std::endl;
            //  std::cout << "A_flag: " << (data.A_flag ? "true" : "false") << std::endl;
            //  std::cout << "L_flag: " << (data.L_flag ? "true" : "false") << std::endl;
            //  std::cout << "T: " << data.T << std::endl;
            //  std::cout << "K: " << (data.K ? data.K : "nullptr") << std::endl;
            //  std::cout << "E: " << (data.E ? data.E : "nullptr") << std::endl;
            //  std::cout << "G: " << (data.G ? data.G : "nullptr") << std::endl;
            //  std::cout << "R: " << data.R << std::endl;
            //  std::cout << "log: " << (data.log ? data.log : "nullptr") << std::endl;
            if (data.A_flag && data.R == -1)
            {
                try
                {
                    // cout << "Encrypting plaintext....." << endl;
                    logger.encrypt_log_plaintext(plaintextNew);
                    // cout << "Encryption of plaintext successful" << endl;
                }
                catch (const runtime_error &e)
                {
                    // cerr << "Encryption of plaintext error: " << e.what() << endl;
                    // return 1; // Return an error code
                    invalid("");
                }
            }
            else
            {
                invalid("");
            }
        }
        else if (status == -1)
        {
            // cout << "Token not verfified for file: " << filename << endl;
            invalid("");
        }
        else
        {
            // cout << "Some error occured during the verification" << endl;
            invalid("");
        }
    }

    return 0;
}
