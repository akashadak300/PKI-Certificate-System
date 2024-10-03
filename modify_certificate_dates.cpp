#include <iostream>
#include <fstream>
#include <string>
#include <sstream>

// Function to modify the certificate dates
void modifyCertificateDates(const std::string& filename, const std::string& newNotBefore, const std::string& newNotAfter) {
    // Read the existing certificate file
    std::ifstream certFile(filename);
    if (!certFile) {
        std::cerr << "Failed to open certificate file: " << filename << std::endl;
        return;
    }

    std::stringstream certStream;
    certStream << certFile.rdbuf();
    std::string certData = certStream.str();
    certFile.close();

    // Find and replace the NotBefore and NotAfter dates
    size_t startPos = certData.find("NotBefore: ");
    size_t endPos = certData.find("\n", startPos);
    if (startPos != std::string::npos && endPos != std::string::npos) {
        certData.replace(startPos + 10, endPos - startPos - 10, newNotBefore);
    }

    startPos = certData.find("NotAfter: ");
    endPos = certData.find("\n", startPos);
    if (startPos != std::string::npos && endPos != std::string::npos) {
        certData.replace(startPos + 9, endPos - startPos - 9, newNotAfter);
    }

    // Save the modified certificate file
    std::ofstream outFile("Modified_Certificate.bin", std::ios::binary);
    if (!outFile) {
        std::cerr << "Failed to open output file for writing." << std::endl;
        return;
    }

    outFile << certData;
    outFile.close();

    std::cout << "Certificate dates modified and saved as Modified_Certificate.bin" << std::endl;
}

int main(int argc, char* argv[]) {
    // Check if the correct number of command-line arguments are provided
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <certificate_file> <new_not_before_date> <new_not_after_date>" << std::endl;
        return 1;
    }

    // Extract command-line arguments
    std::string certFilename = argv[1];  // Certificate file
    std::string newNotBefore = argv[2];  // New NotBefore date
    std::string newNotAfter = argv[3];   // New NotAfter date

    // Modify the certificate dates
    modifyCertificateDates(certFilename, newNotBefore, newNotAfter);

    return 0;
}
// ./test Certificate.bin "Sun, 01 Jan 2000" "Sat, 01 Jan 2001"
