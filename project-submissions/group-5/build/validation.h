// validation.h
#ifndef VALIDATION_H
#define VALIDATION_H

#include <string>
#include <regex>

// Function to validate filenames
bool isValidFilename(const std::string& filename) {
    if (filename.length() < 1 || filename.length() > 127) {
        return false;
    }
    std::regex valid_chars(R"(^[_\-0-9a-z]([_\-\.0-9a-z]{0,125}[_\-0-9a-z])?$)");
    if (!std::regex_match(filename, valid_chars)) {
        return false;
    }
    if (filename == "." || filename == "..") {
        return false;
    }
    return true;
}

// Function to validate account names
bool isValidAccountName(const std::string& accountName) {
    if (accountName.length() < 1 || accountName.length() > 122) {
        return false;
    }
    // Allow '.' and '..' as valid account names
    if (accountName == "." || accountName == "..") {
        return true;
    }
    // Regular expression to validate the characters in account names
    std::regex valid_chars(R"(^[_\-0-9a-z]([_\-\.0-9a-z]{0,120}[_\-0-9a-z])?$)");
    if (!std::regex_match(accountName, valid_chars)) {
        return false;
    }
    return true;
}

// Function to validate positive numbers without leading zero
bool isValidPositiveNumber(const std::string& number) {
    std::regex valid_number("(0|[1-9][0-9]*)");
    return std::regex_match(number, valid_number);
}

// Function to validate port number
bool isValidPort(int port) {
    return port >= 1024 && port <= 65535;
}

// Function to validate currency amounts
bool isValidCurrencyAmount(const std::string& amount) {
    std::regex valid_currency("([0-9]+)(\\.[0-9]{2})?");
    if (!std::regex_match(amount, valid_currency)) {
        return false;
    }

    // Check if the amount is within the valid range
    size_t pos = amount.find('.');
    unsigned long long whole_part = pos != std::string::npos ? std::stoull(amount.substr(0, pos)) : std::stoull(amount);
    unsigned long long fractional_part = pos != std::string::npos ? std::stoull(amount.substr(pos + 1)) : 0;

    return (whole_part <= 4294967295) && (fractional_part <= 99);
}

// Function to validate IPv4 addresses
bool isValidIPAddress(const std::string& ip) {
    std::regex ip_pattern(R"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\. (25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\. (25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\. (25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))");
    return std::regex_match(ip, ip_pattern);
}

std::string trimLeadingSpaces(const std::string& str) {
    size_t first = str.find_first_not_of(' ');
    return (first == std::string::npos) ? "" : str.substr(first);
}

bool isPositiveDecimal(const std::string &number) {
    std::regex decimalPattern(R"(^0$|^[1-9]\d*(\.\d{1,2})?$)");
    return std::regex_match(number, decimalPattern);
}

#endif // VALIDATION_H
