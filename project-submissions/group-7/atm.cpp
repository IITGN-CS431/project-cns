/************************************************************************************************************************************************************
 *                                                                 CNS-431: Project "ATM"                                                                   *       *
 ************************************************************************************************************************************************************/

//-----------------------------------------------------------------------------------------------------------------------------------------------------------------
//                                                                  IMPORT LIBRARIES
//-----------------------------------------------------------------------------------------------------------------------------------------------------------------

#include <iostream>
#include <sstream>
#include <cstring>
#include <unistd.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <iomanip>
#include <sstream>
#include <arpa/inet.h>
#include <jsoncpp/json/json.h>
#include <random>
#include <getopt.h>
#include <fstream>
#include <regex>
using namespace std;
using namespace Json;

//-----------------------------------------------------------------------------------------------------------------------------------------------------------------
//                                                                  GLOBAL VARIABLES
//-----------------------------------------------------------------------------------------------------------------------------------------------------------------

string AUTH_FILE_PATH = "";
string IP_ADDRESS = "127.0.0.1";
int PORT = 3000;
#define BUFFER_SIZE 4096
string USER_CARD = "";
string ACCOUNT = "";
char MODE = '-';
string BALANCE = "";
string AMOUNT = "";
string SYM_KEY = "";
string IV = "";

//-----------------------------------------------------------------------------------------------------------------------------------------------------------------
//                                                                  UTILITY FUNCTIONS
//-----------------------------------------------------------------------------------------------------------------------------------------------------------------

// ................................  HELP FUNCTION  ................................

void printHelp()
{
    ifstream file = ifstream("help.txt");
    if (file.is_open())
    {
        string line;
        while (getline(file, line))
        {
            cout << line << endl;
        }
        file.close();
    }
    else
    {
        cerr << "help.txt not found!" << endl;
    }
}

// ................................  VALIDATION FUNCTIONS  ................................

bool isValidPort(char *port)
{
    if (strlen(port) > 5)
    {
        return false;
    }
    for (int i = 0; i < strlen(port); i++)
    {
        if (!isdigit(port[i]))
        {
            return false;
        }
    }
    string port_str = port;
    int port_num = stoi(port_str);
    return port_num >= 1024 && port_num <= 65535;
}

bool isValidAmount(char *amount)
{
    if (strlen(amount) > 13)
    {
        return false;
    }

    bool decimal = false;
    int decimal_places = 0;

    for (int i = 0; i < strlen(amount); i++)
    {
        if (!isdigit(amount[i]) && amount[i] != '.')
        {
            return false;
        }
        if (decimal)
        {
            decimal_places++;
            if (decimal_places > 2)
            {
                return false;
            }
        }
        if (amount[i] == '.' && decimal == false)
        {
            decimal = true;
        }
        else if (amount[i] == '.')
        {
            return false;
        }
    }

    double amount_num = stod(string(amount));
    return amount_num >= 0.00 && amount_num <= 4294967295.99;
}

bool isValidIP(const string &ip)
{
    int num;
    char ch;
    istringstream stream(ip);

    for (int i = 0; i < 4; i++)
    {
        if (!(stream >> num) || num < 0 || num > 255)
        {
            return false;
        }

        if (i < 3)
        {
            if (!(stream >> ch) || ch != '.')
            {
                return false;
            }
        }
    }

    return stream.eof();
}

bool isValidFileName(const string &fileName)
{
    if (fileName.length() < 6 || fileName.length() > 127)
    {
        return false;
    }
    string extension = fileName.substr(fileName.length() - 5);
    if (extension != ".card")
    {
        return false;
    }
    string name = fileName.substr(0, fileName.length() - 5);
    if (name == "." || name == "..")
    {
        return false;
    }

    regex validPattern("^[-_.0-9a-z]+$");

    return regex_match(name, validPattern);
}

bool isValidAccountName(const string &account)
{
    if (account.length() < 1 || account.length() > 122)
    {
        return false;
    }

    regex validPattern("^[-_.0-9a-z]+$");

    return regex_match(account, validPattern);
}

// ................................  PARSING FUNCTIONS  ................................

void check_req_args(string &error)
{
    if (AUTH_FILE_PATH == "")
    {
        error += "ATM authentication failed! Missing argument -s [...]\n";
    }
    if (USER_CARD == "")
    {
        error += "User authentication failed! Missing argument -c [...] \n";
    }
    if (MODE == '-')
    {
        error += "No mode specified! Missing argument -n [...] or -d [...] or -w [...] or -g \n";
    }
    if (ACCOUNT == "")
    {
        error += "No account specified! Missing argument -a [...] \n";
    }
    else if (!isValidAccountName(ACCOUNT))
    {
        error += "Invalid account name! Account name must be alphanumeric and can contain only the following characters: -_. \n";
    }
}

void parseArguments(int argc, char *argv[], string &error)
{
    int opt;

    while ((opt = getopt(argc, argv, "hs:i:p:a:c:n:d:w:g")) != -1)
    {
        switch (opt)
        {
        case 'h':
            printHelp();
            exit(0);

        case 's':
            AUTH_FILE_PATH = optarg;
            break;

        case 'i':
            if (isValidIP(optarg))
            {
                IP_ADDRESS = optarg;
            }
            else
            {
                error = "Invalid IP address! IP address must be a valid IPv4 address. \n";
            }
            break;

        case 'p':
            if (isValidPort(optarg))
            {
                PORT = stoi(optarg);
            }
            else
            {
                error = "Invalid port number! Port number must be an integer between 1024 and 65535. \n";
            }
            break;

        case 'c':
            if (isValidFileName(optarg))
            {
                USER_CARD = optarg;
            }
            else
            {
                error = "Invalid card file name! Card file name must be a valid file name with a .card extension. \n";
            }
            break;
        case 'a':
            ACCOUNT = optarg;
            break;
        case 'n':
            if (MODE == '-')
                MODE = 'n';
            else
            {
                error = "Specifying multiple modes is not allowed! \n";
            }
            if (isValidAmount(optarg))
            {
                BALANCE = optarg;
            }
            else
            {
                error = "Invalid balance! Balance must be a positive number with only upto 2 decimal places from 0.00 to 4294969295.99 \n";
            }
            break;
        case 'd':
            if (MODE == '-')
                MODE = 'd';
            else
            {
                error = "Specifying multiple modes is not allowed! \n";
            }
            if (isValidAmount(optarg))
            {
                AMOUNT = optarg;
            }
            else
            {
                error = "Invalid amount! Amount must be a positive number with only upto 2 decimal places from 0.00 to 4294969295.99 \n";
            }
            break;
        case 'w':
            if (MODE == '-')
                MODE = 'w';
            else
            {
                error = "Specifying multiple modes is not allowed! \n";
            }
            if (isValidAmount(optarg))
            {
                AMOUNT = optarg;
            }
            else
            {
                error = "Invalid amount! Amount must be a positive number with only upto 2 decimal places from 0.00 to 4294969295.99 \n";
            }
            break;
        case 'g':
            if (MODE == '-')
                MODE = 'g';
            else
            {
                error = "Specifying multiple modes is not allowed! \n";
            }
            break;
        default:
            cerr << "Invalid argument! Run ./atm -h to get help." << endl;
            exit(255);
        }
    }

    check_req_args(error);
}

// ................................  GENERATION FUNCTIONS  ................................

void generateKeyAndIV(string &key, string &iv)
{
    const string characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    random_device rd;
    mt19937 generator(rd());
    uniform_int_distribution<> distribution(0, characters.size() - 1);

    for (int i = 0; i < 128; i++)
    {
        key += characters[distribution(generator)];
    }
    for (int i = 0; i < 16; i++)
    {
        iv += characters[distribution(generator)];
    }
    return;
}
string generateRandomPassword(int length = 32)
{
    const string characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789~!@#$%^&*()_+-=:;,.<>/?";
    random_device rd;
    mt19937 generator(rd());
    uniform_int_distribution<> distribution(0, characters.size() - 1);

    string password;
    for (int i = 0; i < length; ++i)
    {
        password += characters[distribution(generator)];
    }
    return password;
}

void generateRSAKeyPairs()
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *pkey = NULL;

    if (!ctx)
    {
        cerr << "Error initializing context for RSA key generation\n";
        return;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        cerr << "Error initializing key generation\n";
        EVP_PKEY_CTX_free(ctx);
        return;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0)
    {
        cerr << "Error setting RSA key size\n";
        EVP_PKEY_CTX_free(ctx);
        return;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
    {
        cerr << "Error generating RSA key pair\n";
        EVP_PKEY_CTX_free(ctx);
        return;
    }

    FILE *privateKeyFile = fopen("private_key.pem", "wb");
    FILE *publicKeyFile = fopen("public_key.pem", "wb");

    if (!privateKeyFile || !publicKeyFile)
    {
        cerr << "Error opening key files\n";
        return;
    }

    if (!PEM_write_PrivateKey(privateKeyFile, pkey, NULL, NULL, 0, NULL, NULL))
    {
        cerr << "Error writing private key\n";
        fclose(privateKeyFile);
        fclose(publicKeyFile);
        return;
    }

    if (!PEM_write_PUBKEY(publicKeyFile, pkey))
    {
        cerr << "Error writing public key\n";
        fclose(privateKeyFile);
        fclose(publicKeyFile);
        return;
    }

    fclose(privateKeyFile);
    fclose(publicKeyFile);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
}

string generateMAC(const string &key, const string &iv, const string &message)
{
    string data = iv + message;

    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int mac_size = 0;

    HMAC(EVP_sha256(), key.data(), key.size(), reinterpret_cast<const unsigned char *>(data.data()), data.size(), mac, &mac_size);

    mac_size = min(mac_size, static_cast<unsigned int>(32));
    string message_with_mac = message + string(reinterpret_cast<const char *>(mac), mac_size);

    return message_with_mac;
}

// ................................  ENCRYPTION-DECRYPTION FUNCTIONS  ................................

string encryptUsingPublicKey(string &message)
{
    FILE *publicKeyFile = fopen("public_key.pem", "rb");
    if (!publicKeyFile)
    {
        cerr << "Error opening public key file\n";
        return "";
    }

    EVP_PKEY *publicKey = PEM_read_PUBKEY(publicKeyFile, NULL, NULL, NULL);
    fclose(publicKeyFile);

    if (!publicKey)
    {
        cerr << "Error reading public key\n";
        return "";
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(publicKey, NULL);
    if (!ctx)
    {
        EVP_PKEY_free(publicKey);
        cerr << "Error creating context for encryption\n";
        return "";
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(publicKey);
        cerr << "Error initializing encryption\n";
        return "";
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(publicKey);
        cerr << "Error setting padding\n";
        return "";
    }

    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, (const unsigned char *)message.c_str(), message.length()) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(publicKey);
        cerr << "Error determining buffer size for encryption\n";
        return "";
    }

    vector<unsigned char> outbuf(outlen);

    if (EVP_PKEY_encrypt(ctx, outbuf.data(), &outlen, (const unsigned char *)message.c_str(), message.length()) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(publicKey);
        cerr << "Error encrypting data\n";
        return "";
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(publicKey);

    string final_output;
    for (auto c : outbuf)
    {
        final_output.push_back(c);
    }

    return final_output;
}

string decryptUsingPrivateKey(string &message)
{
    FILE *privateKeyFile = fopen("private_key.pem", "rb");
    if (!privateKeyFile)
    {
        cerr << "Error opening private key file\n";
        return "";
    }

    EVP_PKEY *privateKey = PEM_read_PrivateKey(privateKeyFile, NULL, NULL, NULL);
    fclose(privateKeyFile);

    if (!privateKey)
    {
        cerr << "Error reading private key\n";
        return "";
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privateKey, NULL);
    if (!ctx)
    {
        EVP_PKEY_free(privateKey);
        cerr << "Error creating context for decryption\n";
        return "";
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privateKey);
        cerr << "Error initializing decryption\n";
        return "";
    }

    size_t outlen;
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, (const unsigned char *)message.c_str(), message.length()) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privateKey);
        cerr << "Error determining buffer size for decryption\n";
        return "";
    }

    vector<unsigned char> outbuf(outlen);

    if (EVP_PKEY_decrypt(ctx, outbuf.data(), &outlen, (const unsigned char *)message.c_str(), message.length()) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privateKey);
        cerr << "Error decrypting data\n";
        return "";
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(privateKey);

    return string(outbuf.begin(), outbuf.end());
}
// Convert byte array to hex string
string to_hex_string(const vector<unsigned char> &data)
{
    ostringstream oss;
    for (auto byte : data)
    {
        oss << hex << setw(2) << setfill('0') << static_cast<int>(byte);
    }
    return oss.str();
}

// Convert hex string to byte array
vector<unsigned char> from_hex_string(const string &hex)
{
    vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2)
    {
        string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(stoi(byteString, nullptr, 16));

        bytes.push_back(byte);
    }
    return bytes;
}

// Handle OpenSSL errors
void handleErrors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

// Encryption function
string encryptUsingSYM_KEY(const string &key, const string &iv, const string &plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;
    int ciphertext_len;
    vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    // Initialize the encryption operation with 256-bit AES in CBC mode
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char *)key.data(), (unsigned char *)iv.data()))
        handleErrors();

    // Provide the plaintext to encrypt and obtain the encrypted output
    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (unsigned char *)plaintext.data(), plaintext.size()))
        handleErrors();
    ciphertext_len = len;

    // Finalize the encryption (handle padding)
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len))
        handleErrors();
    ciphertext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    // Return ciphertext as hex string
    ciphertext.resize(ciphertext_len);
    return to_hex_string(ciphertext);
}

// Decryption function
string decryptUsingSYM_KEY(const string &key, const string &iv, const string &ciphertext_hex)
{
    EVP_CIPHER_CTX *ctx;

    int len;
    int plaintext_len;
    vector<unsigned char> plaintext(ciphertext_hex.size());

    // Convert hex string back to bytes
    vector<unsigned char> ciphertext = from_hex_string(ciphertext_hex);

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    // Initialize the decryption operation with 256-bit AES in CBC mode
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char *)key.data(), (unsigned char *)iv.data()))
        handleErrors();

    // Provide the ciphertext to decrypt and obtain the plaintext output
    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()))
        handleErrors();
    plaintext_len = len;

    // Finalize the decryption (handle padding)
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len))
        handleErrors();
    plaintext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    // Return plaintext as string
    plaintext.resize(plaintext_len);
    return string(plaintext.begin(), plaintext.end());
}

//-----------------------------------------------------------------------------------------------------------------------------------------------------------------
//                                                                  COMMUNICATION FUNCTIONS
//-----------------------------------------------------------------------------------------------------------------------------------------------------------------

// Function send a message to the bank server
string sendMessageToServer(const string &message, const string &ip, int port)
{
    int sockfd;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE];

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Socket creation failed");
        exit(255);
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip.c_str(), &serv_addr.sin_addr) <= 0)
    {
        cerr << "Invalid IP address" << endl;
        exit(255);
    }

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("Connection to the bank server failed");
        exit(255);
    }

    memset(buffer, 0, BUFFER_SIZE);
    cout << "Connecting with the Bank Server..." << endl;

    generateKeyAndIV(SYM_KEY, IV);

    string key_iv = SYM_KEY + IV;
    string key_iv_message;
    while (true)
    {
        key_iv_message = encryptUsingPublicKey(key_iv);
        if (string(key_iv_message.c_str()).size() == 256)
        {
            break;
        }
    }
    key_iv_message.append("1");
    // Sending the Key and IV to the Bank Server for further communication
    send(sockfd, key_iv_message.c_str(), key_iv_message.size(), 0);
    sleep(0.5);

    // Sending the Request to the Bank Server
    string mess = message;
    string encrypted_message = encryptUsingSYM_KEY(SYM_KEY, IV, mess);
    send(sockfd, encrypted_message.c_str(), encrypted_message.size(), 0);

    int n = read(sockfd, buffer, BUFFER_SIZE - 1);
    string response = decryptUsingSYM_KEY(SYM_KEY, IV, string(buffer));
    if (n > 0)
    {
        cout << "Response from the Bank Server: \n"
             << response << endl;
    }
    else
    {
        cerr << "Error: No second response received from the server." << endl;
    }

    close(sockfd);
    return string(buffer);
}

// ................................  ATM FUNCTIONALITIES ................................

void createNewAccount(const string &account, string &balance, const string &cardFile, const string &ip, int port)
{
    ifstream infile(cardFile);
    if (infile.good())
    {
        cerr << "Card file already exists" << endl;
        exit(255);
    }

    string password = generateRandomPassword();
    ifstream AuthFile(AUTH_FILE_PATH);
    if (!AuthFile)
    {
        cerr << "Bank authentication file not found" << endl;
        exit(255);
    }
    string AUTH_CONTENT;
    AuthFile >> AUTH_CONTENT;
    AuthFile.close();

    Value jsonMessage;
    jsonMessage["auth"] = AUTH_CONTENT;
    jsonMessage["mode"] = "n";
    jsonMessage["account"] = account;
    jsonMessage["password"] = password;
    jsonMessage["initial_balance"] = balance;
    StreamWriterBuilder writer;
    string message = writeString(writer, jsonMessage);

    string response = string(sendMessageToServer(message, ip, port));
    if (response.find("Error Occured") != string::npos)
    {
        exit(255);
    }
    ofstream outfile(cardFile);
    if (!outfile)
    {
        cerr << "Failed to create card file" << endl;
        exit(255);
    }
    outfile << password;
    outfile.close();
}

void depositMoney(const string &account, string &amount, const string &cardFile, const string &ip, int port)
{
    ifstream infile(cardFile);
    if (!infile)
    {
        cerr << "Card file not found" << endl;
        exit(255);
    }

    string password;
    infile >> password;
    infile.close();
    ifstream AuthFile(AUTH_FILE_PATH);
    if (!AuthFile)
    {
        cerr << "Bank authentication file not found" << endl;
        exit(255);
    }
    string AUTH_CONTENT;
    AuthFile >> AUTH_CONTENT;
    AuthFile.close();

    Value jsonMessage;
    jsonMessage["auth"] = AUTH_CONTENT;
    jsonMessage["mode"] = "d";
    jsonMessage["account"] = account;
    jsonMessage["password"] = password;
    jsonMessage["amount"] = amount;
    StreamWriterBuilder writer;
    string message = writeString(writer, jsonMessage);

    sendMessageToServer(message, ip, port);
}

void withdrawMoney(const string &account, string &amount, const string &cardFile, const string &ip, int port)
{
    ifstream infile(cardFile);
    if (!infile)
    {
        cerr << "Card file not found" << endl;
        exit(255);
    }
    string password;
    infile >> password;
    infile.close();
    ifstream AuthFile(AUTH_FILE_PATH);
    if (!AuthFile)
    {
        cerr << "Bank authentication file not found" << endl;
        exit(255);
    }
    string AUTH_CONTENT;
    AuthFile >> AUTH_CONTENT;
    AuthFile.close();

    Value jsonMessage;
    jsonMessage["auth"] = AUTH_CONTENT;
    jsonMessage["mode"] = "w";
    jsonMessage["account"] = account;
    jsonMessage["password"] = password;
    jsonMessage["amount"] = amount;
    StreamWriterBuilder writer;
    string message = writeString(writer, jsonMessage);

    sendMessageToServer(message, ip, port);
}

void getBalance(const string &account, const string &cardFile, const string &ip, int port)
{
    ifstream infile(cardFile);
    if (!infile)
    {
        cerr << "Card file not found" << endl;
        exit(255);
    }
    string password;
    infile >> password;
    infile.close();
    // Now read bank.auth file and get the ATM's public key
    ifstream AuthFile(AUTH_FILE_PATH);
    if (!AuthFile)
    {
        cerr << "Bank authentication file not found" << endl;
        exit(255);
    }
    string AUTH_CONTENT;
    AuthFile >> AUTH_CONTENT;
    AuthFile.close();

    Value jsonMessage;
    jsonMessage["auth"] = AUTH_CONTENT;
    jsonMessage["mode"] = "g";
    jsonMessage["account"] = account;
    jsonMessage["password"] = password;
    StreamWriterBuilder writer;
    string message = writeString(writer, jsonMessage);

    sendMessageToServer(message, ip, port);
}

//-----------------------------------------------------------------------------------------------------------------------------------------------------------------
//                                                                  MAIN FUNCTION
//-----------------------------------------------------------------------------------------------------------------------------------------------------------------

int main(int argc, char *argv[])
{
    // ------------------- Parse the command line arguments --------------------------
    string error;

    parseArguments(argc, argv, error);

    if (error != "")
    {
        error += "Run ./atm -h to get help. \n";
        cerr << error;
        exit(255);
    }

    // ------------------- Perform the ATM operation based on the mode --------------------------

    switch (MODE)
    {
    case 'n':
        createNewAccount(ACCOUNT, BALANCE, USER_CARD, IP_ADDRESS, PORT);
        break;
    case 'd':
        depositMoney(ACCOUNT, AMOUNT, USER_CARD, IP_ADDRESS, PORT);
        break;
    case 'w':
        withdrawMoney(ACCOUNT, AMOUNT, USER_CARD, IP_ADDRESS, PORT);
        break;
    case 'g':
        getBalance(ACCOUNT, USER_CARD, IP_ADDRESS, PORT);
        break;
    default:
        cout << "Invalid Mode Specified" << endl;
        exit(255);
    }

    return 0;
}