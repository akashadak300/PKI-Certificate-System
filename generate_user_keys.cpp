#include <cryptopp/rsa.h>         // Include the header for RSA cryptographic functions from Crypto++.
#include <cryptopp/osrng.h>       // Include the header for AutoSeededRandomPool, a secure random number generator.
#include <cryptopp/files.h>       // Include the header for file handling, to read/write keys to files.
#include <cryptopp/cryptlib.h>    // Include the header for Crypto++ exceptions and base classes.
#include <iostream>               // Include the standard input/output stream library.

using namespace CryptoPP;         // Use the CryptoPP namespace to avoid prefixing CryptoPP types with "CryptoPP::".
using namespace std;              // Use the standard namespace to avoid prefixing with "std::".

int main() {
    try {
        AutoSeededRandomPool rng;   // Create an instance of a secure random number generator.
        
        RSA::PrivateKey privateKey; // Declare an RSA private key object.
        RSA::PublicKey publicKey;   // Declare an RSA public key object.

        // Generate a 1024-bit RSA private key using the random number generator.
        privateKey.GenerateRandomWithKeySize(rng, 1024);

        // Assign the corresponding public key from the generated private key.
        publicKey.AssignFrom(privateKey);

        // Create a file sink to write the private key to "User_Priv.bin" in DER format.
        FileSink privateKeyFile("User_Priv.bin", true);
        // Encode the private key in DER format and write it to the file.
        privateKey.DEREncode(privateKeyFile);
        // Finalize the write operation.
        privateKeyFile.MessageEnd();

        // Create a file sink to write the public key to "User_Pub.bin" in DER format.
        FileSink publicKeyFile("User_Pub.bin", true);
        // Encode the public key in DER format and write it to the file.
        publicKey.DEREncode(publicKeyFile);
        // Finalize the write operation.
        publicKeyFile.MessageEnd();

        // Output messages to indicate successful key generation and file saving.
        cout << "User keys successfully generated!" << endl;
        cout << "Private Key saved as: User_Priv.bin" << endl;
        cout << "Public Key saved as: User_Pub.bin" << endl;

    } catch(const Exception& e) {  // Catch any exceptions thrown by the Crypto++ library.
        // Print the error message to standard error output.
        cerr << "An error occurred during key generation: " << e.what() << endl;
        return 1;  // Return a non-zero value to indicate an error occurred.
    }

    return 0;  // Return 0 to indicate successful execution.
}
