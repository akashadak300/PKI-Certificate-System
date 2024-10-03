# PKI Certificate Signing and Verification System

## Project Overview
The **PKI Certificate Signing and Verification System** is a project designed to implement the fundamentals of Public Key Infrastructure (PKI) by creating and verifying digital certificates. The project simulates how a Certificate Authority (CA) issues certificates and how those certificates are verified to establish secure communication.

### Objectives:
- **Setup Phase**: Generate public-private key pairs for the Certificate Authority (CA) and the users.
- **Key Generation**: Generate separate public-private key pairs for users.
- **Certificate Issuance**: Use the CA's private key to sign certificates for users, embedding user information and public keys.
- **Certificate Verification**: Verify the authenticity of the certificates by checking the digital signature and the validity period.

## Features
1. **RSA Key Generation**: Generates RSA keys for both the CA (2048-bit) and users (1024-bit).
2. **Certificate Signing**: Issues digital certificates with user information and public key, signed by the CA using DSA (Digital Signature Algorithm).
3. **Certificate Verification**: Verifies the authenticity of a certificate by validating the signature and checking the certificate's validity period.

## Project Structure

### 1. Setup Phase
- **Objective**: Generate a 2048-bit RSA public-private key pair for the CA.
- **Output**: 
  - `CA_Pub.bin`: Public key of the CA.
  - `CA_Priv.bin`: Private key of the CA.

### 2. Key Generation (KeyGen)
- **Objective**: Generate a 1024-bit RSA key pair for the user.
- **Output**: 
  - `User_Pub.bin`: Public key of the user.
  - `User_Priv.bin`: Private key of the user.

### 3. Certificate Issuance (IssueCertificate)
- **Objective**: Issue a digital certificate for the user.
- **Input**: 
  - User's email ID, CA private key (`CA_Priv.bin`), User's public key (`User_Pub.bin`).
- **Output**: 
  - `Certificate.bin`: Signed digital certificate containing the user’s public key, ID, validity, and the CA's signature.

#### Certificate Structure:
- **Issuer Name**: IIITA
- **Subject ID**: User email ID
- **Validity**:
  - NotBefore: Sun, 16 Jun 2024
  - NotAfter: Sun, 22 Jun 2026
- **Signature Algorithm**: DSA
- **Subject PublicKey**: RSA public key of the user
- **Signature**: Digital Signature by the CA

### 4. Certificate Verification (VerifyCertificate)
- **Objective**: Verify the digital certificate's authenticity.
- **Input**: 
  - `Certificate.bin`, `CA_Pub.bin`
- **Output**: 
  - Prints `Success` if the certificate is valid; `Failure` otherwise.

## Cryptographic Concepts Used
- **RSA (Rivest-Shamir-Adleman)**: Used to generate public-private key pairs for both the CA and users.
  - CA: 2048-bit key
  - Users: 1024-bit key
- **DSA (Digital Signature Algorithm)**: Used to sign the digital certificates, ensuring authenticity.
- **SHA-256**: Used to hash the certificate data before signing.

## Tools & Technologies
- **Crypto++ Library**: A C++ class library used for cryptographic functions such as RSA, DSA, and SHA-256.
- **C++**: Core programming language used to implement key generation, certificate issuance, and verification.

## How to Run
1. **Setup Phase**: 
   ```bash
   ./setup
