#include <cryptopp/dsa.h>        // Include the header for the Digital Signature Algorithm (DSA) from Crypto++.
#include <cryptopp/sha.h>        // Include the header for SHA (Secure Hash Algorithm) from Crypto++.
#include <cryptopp/files.h>      // Include the header for file handling in Crypto++.
#include <cryptopp/base64.h>     // Include the header for Base64 encoding/decoding.
#include <cryptopp/hex.h>        // Include the header for Hex encoding/decoding.
#include <cryptopp/osrng.h>      // Include the header for secure random number generation.
#include <iostream>              // Include the standard input/output stream library.
#include <fstream>               // Include the file stream library for file operations.
#include <string>                // Include the string library for handling text.
#include <sstream>               // Include the string stream library for text stream operations.
#include <ctime>                 // Include the time library for handling dates and times.

// Function to parse date strings and convert them to time_t
time_t parseDate(const std::string& dateStr) {
    struct tm tm = {};                      // Create a structure to hold the parsed date and time.
    strptime(dateStr.c_str(), "%a, %d %b %Y", &tm);  // Parse the date string using the format "Day, DD Mon YYYY".
    return mktime(&tm);                    // Convert the parsed date and time to time_t for easy comparison.
}

// Function to print data in Hex format
void printHex(const std::string& data) {
    std::string encoded;                           // String to hold the encoded Hex output.
    CryptoPP::StringSource ss(data, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(encoded)));  // Encode the data in Hex format.
    std::cout << encoded << std::endl;            // Print the Hex-encoded data.
}

// Function to validate certificate dates
// bool validateDates(const std::string& notBefore, const std::string& notAfter) {
//     time_t now = time(0);                         // Get the current time.
//     time_t startDate = parseDate(notBefore);      // Parse the "NotBefore" date from the certificate.
//     time_t endDate = parseDate(notAfter);         // Parse the "NotAfter" date from the certificate.

//     // Check if the current time is within the validity period of the certificate.
//     return (now >= startDate && now <= endDate);
// }

int main(int argc, char* argv[]) {
    // Check if the correct number of command-line arguments are provided.
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <certificate_file> <CA_public_key_file>" << std::endl;
        return 1;  // Return an error code if the arguments are incorrect.
    }

    std::string certFilename = argv[1];  // Certificate file path from command-line argument.
    std::string caPubKeyFilename = argv[2];  // CA public key file path from command-line argument.

    try {
        // Load CA's public DSA key from the specified file.
        CryptoPP::DSA::PublicKey caPublicKey;
        CryptoPP::FileSource fs(caPubKeyFilename.c_str(), true /*pumpAll*/);
        caPublicKey.Load(fs);

        // Read the certificate file.
        std::ifstream certFile(certFilename);
        if (!certFile) {
            std::cerr << "Failed to open certificate file: " << certFilename << std::endl;
            return 1;  // Return an error code if the file cannot be opened.
        }

        // Read the entire certificate file into a string.
        std::stringstream certStream;
        certStream << certFile.rdbuf();
        std::string certData = certStream.str();  // Store the certificate data as a string.
        certFile.close();  // Close the certificate file.

        // Parse certificate body and extract signature.
        size_t sigPos = certData.find("Signature: ");  // Find the position of the signature in the certificate data.
        if (sigPos == std::string::npos) {
            std::cerr << "Failed to find signature in certificate." << std::endl;
            return 1;  // Return an error code if the signature is not found.
        }

        // Extract the certificate body and signature from the certificate data.
        std::string certBody = certData.substr(0, sigPos);
        std::string signatureBase64 = certData.substr(sigPos + 10);

        // Decode the signature from Base64 format.
        std::string signature;
        CryptoPP::StringSource ss(signatureBase64, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(signature)));

        // Hash the certificate body using SHA-256.
        CryptoPP::SHA256 hash;
        std::string certHash;
        CryptoPP::StringSource(certBody, true, new CryptoPP::HashFilter(hash, new CryptoPP::StringSink(certHash)));

        std::cout << "Certificate Hash (Hex): ";
        printHex(certHash);  // Print the hashed certificate data in Hex format.

        std::cout << "Signature (Decoded Hex): ";
        printHex(signature);  // Print the decoded signature in Hex format.

        // Extract the "NotBefore" and "NotAfter" dates from the certificate body for validation.
        std::string notBefore, notAfter;
        size_t startPos = certBody.find("NotBefore: ");
        size_t endPos = certBody.find("\n", startPos);
        if (startPos != std::string::npos && endPos != std::string::npos) {
            notBefore = certBody.substr(startPos + 10, endPos - startPos - 10);
        }

        startPos = certBody.find("NotAfter: ");
        endPos = certBody.find("\n", startPos);
        if (startPos != std::string::npos && endPos != std::string::npos) {
            notAfter = certBody.substr(startPos + 9, endPos - startPos - 9);
        }

        // Validate the certificate dates against the current date.
        // if (!validateDates(notBefore, notAfter)) {
        //     std::cerr << "Certificate is not valid based on the current date." << std::endl;
        //     return 1;  // Return an error code if the certificate is not valid.
        // }

        // Verify the signature using CA's public key.
        CryptoPP::DSA::Verifier verifier(caPublicKey);
        bool result = verifier.VerifyMessage(reinterpret_cast<const CryptoPP::byte*>(certHash.data()), certHash.size(), reinterpret_cast<const CryptoPP::byte*>(signature.data()), signature.size());

        if (result) {
            std::cout << "Signature verification succeeded." << std::endl;  // Print success message if verification succeeds.
        } else {
            std::cout << "Signature verification failed." << std::endl;  // Print failure message if verification fails.
        }

    } catch (const CryptoPP::Exception& e) {
        std::cerr << "An error occurred: " << e.what() << std::endl;  // Print any errors encountered during execution.
        return 1;  // Return an error code if an exception is caught.
    }

    return 0;  // Return 0 to indicate successful execution.
}
// Compile with: g++ verify_certificate.cpp -o test -lcryptopp
// Run with: ./test Certificate.bin CA_Pub.bin
