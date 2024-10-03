#include <cryptopp/dsa.h>
#include <cryptopp/rsa.h>
#include <cryptopp/sha.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/hex.h>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>

using namespace CryptoPP;
using namespace std;

int main(int argc, char* argv[]) {
    // Check if the correct number of command-line arguments are provided
    if (argc != 7) {
        cout << "Usage: " << argv[0] << " <issuer_name> <not_before> <not_after> <user_email> <CA_private_key_file> <user_public_key_file>" << endl;
        return 1;  // Return an error code if the arguments are incorrect
    }

    // Extract command-line arguments
    string issuerName = argv[1];  // Issuer name
    string notBefore = argv[2];   // Validity start date
    string notAfter = argv[3];    // Validity end date
    string userEmail = argv[4];   // User's email, which will be used as the subject ID in the certificate
    string caPrivKeyFilename = argv[5];  // Filename of the CA's private key
    string userPubKeyFilename = argv[6];  // Filename of the user's public key

    try {
        AutoSeededRandomPool rng;  // Create a secure random number generator

        // Load the CA's private DSA key from the specified file
        DSA::PrivateKey caPrivateKey;
        FileSource fs1(caPrivKeyFilename.c_str(), true /*pumpAll*/);
        caPrivateKey.Load(fs1);

        // Load the user's RSA public key from the specified file
        RSA::PublicKey userPublicKey;
        FileSource fs2(userPubKeyFilename.c_str(), true /*pumpAll*/);
        userPublicKey.Load(fs2);

        // Start building the certificate body using a string stream
        stringstream certStream;
        certStream << "Issuer Name: " << issuerName << "\n";  // Add the issuer name to the certificate
        certStream << "Subject ID: " << userEmail << "\n";  // Add the subject ID (user's email) to the certificate
        certStream << "Validity:\n";  // Add the validity period of the certificate
        certStream << "  NotBefore: " << notBefore << "\n";  // Certificate is valid from this date
        certStream << "  NotAfter: " << notAfter << "\n";  // Certificate is valid until this date
        certStream << "Signature Algorithm: DSA\n";  // Specify the signature algorithm used
        certStream << "Subject PublicKey: (RSA) ";  // Indicate that the subject's public key is an RSA key

        // Encode the user's RSA public key in Base64 format
        string encodedPubKey;
        StringSink* ssPubKey = new StringSink(encodedPubKey);
        Base64Encoder pubKeyEncoder(ssPubKey);
        userPublicKey.DEREncode(pubKeyEncoder);
        pubKeyEncoder.MessageEnd();
// Overall, Base64 encoding helps ensure that binary data like
//  cryptographic keys can be safely represented and transmitted as plain text.
        certStream << encodedPubKey << "\n";  // Append the encoded public key to the certificate body

        // Get the certificate data for hashing and signing
        string certData = certStream.str();  // Convert the certificate stream to a string
        cout << "Certificate Data:\n" << certData << endl;  // Print the certificate data for verification

        // Hash the certificate data using SHA-256
        SHA256 hash;
        string certHash;
        StringSource(certData, true, new HashFilter(hash, new StringSink(certHash)));

        // Display the hashed certificate data in hexadecimal format
        cout << "Certificate Hash (Hex): ";
        StringSource(certHash, true, new HexEncoder(new FileSink(cout)));  // Encode the hash in hex and print it
        cout << endl;

        // Sign the hash of the certificate data using the CA's private DSA key
        DSA::Signer signer(caPrivateKey);
        string signature;
        StringSource ss(certHash, true, new SignerFilter(rng, signer, new StringSink(signature)));

        // Encode the signature in Base64 format
        string signatureBase64;
        StringSource(signature, true, new Base64Encoder(new StringSink(signatureBase64)));

        // Save the certificate and the Base64-encoded signature to a file
        ofstream certFile("Certificate.bin", ios::binary);
        certFile << certData;  // Write the certificate data to the file
        certFile << "Signature: " << signatureBase64 << "\n";  // Write the Base64-encoded signature to the file
        certFile.close();  // Close the file after writing

        cout << "Certificate successfully generated as Certificate.bin" << endl;  // Indicate successful generation

    } catch (const Exception& e) {  // Catch any exceptions thrown by the Crypto++ library
        cerr << "An error occurred: " << e.what() << endl;  // Print the error message to standard error output
        return 1;  // Return an error code to indicate failure
    }

    return 0;  // Return 0 to indicate successful execution
}
// ./test "IIITA" "Mon, 01 Jan 2024" "Wed, 01 Jan 2026" "user@example.com" CA_Priv.bin User_Pub.bin
