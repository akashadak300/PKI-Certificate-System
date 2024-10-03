#include <cryptopp/dsa.h>         // Include the header for DSA (Digital Signature Algorithm) from Crypto++.
#include <cryptopp/osrng.h>       // Include the header for AutoSeededRandomPool, a secure random number generator.
#include <cryptopp/files.h>       // Include the header for file handling, to read/write keys to files.
#include <cryptopp/cryptlib.h>    // Include the header for Crypto++ exceptions and base classes.
#include <iostream>               // Include the standard input/output stream library.

using namespace CryptoPP;         // Use the CryptoPP namespace to avoid prefixing CryptoPP types with "CryptoPP::".

int main() {
    try {
        AutoSeededRandomPool rng;   // Create an instance of a secure random number generator.
        
        DSA::PrivateKey privateKey; // Declare a DSA private key object.
        DSA::PublicKey publicKey;   // Declare a DSA public key object.

        // Generate a 2048-bit DSA private key using the random number generator.
        privateKey.GenerateRandomWithKeySize(rng, 2048);

        // Assign the corresponding public key from the generated private key.
        publicKey.AssignFrom(privateKey);

        // Create a file sink to write the private key to "CA_Priv.bin" in DER format.
        FileSink privateKeyFile("CA_Priv.bin", true);
        // Encode the private key in DER format and write it to the file.
        privateKey.DEREncode(privateKeyFile);
        // Finalize the write operation.
        privateKeyFile.MessageEnd();

        // Create a file sink to write the public key to "CA_Pub.bin" in DER format.
        FileSink publicKeyFile("CA_Pub.bin", true);
        // Encode the public key in DER format and write it to the file.
        publicKey.DEREncode(publicKeyFile);
        // Finalize the write operation.
        publicKeyFile.MessageEnd();

        // Output messages to indicate successful key generation and file saving.
        std::cout << "Keys successfully generated!" << std::endl;
        std::cout << "Private Key saved as: CA_Priv.bin" << std::endl;
        std::cout << "Public Key saved as: CA_Pub.bin" << std::endl;

    } catch(const Exception& e) {  // Catch any exceptions thrown by the Crypto++ library.
        // Print the error message to standard error output.
        std::cerr << "An error occurred during key generation: " << e.what() << std::endl;
        return 1;  // Return a non-zero value to indicate an error occurred.
    }

    return 0;  // Return 0 to indicate successful execution.
}

