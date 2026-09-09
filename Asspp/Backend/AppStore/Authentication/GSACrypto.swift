//
//  GSACrypto.swift
//  Asspp
//
//  Cryptographic primitives used by the GSA (Apple ID) SRP login flow.
//  SHA-256/HMAC come from CryptoKit; PBKDF2 and AES-CBC come from CommonCrypto.
//

import CommonCrypto
import CryptoKit
import Foundation

enum GSACrypto {
    static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    static func hmacSHA256(key: Data, message: Data) -> Data {
        let symmetricKey = SymmetricKey(data: key)
        return Data(HMAC<SHA256>.authenticationCode(for: message, using: symmetricKey))
    }

    static func pbkdf2SHA256(
        password: Data,
        salt: Data,
        iterations: Int,
        keyLength: Int
    ) throws -> Data {
        guard iterations > 0, keyLength > 0 else {
            throw GSAError.malformedResponse("invalid PBKDF2 parameters")
        }

        var derived = [UInt8](repeating: 0, count: keyLength)
        let passwordCount = password.count
        let saltCount = salt.count
        let status = derived.withUnsafeMutableBytes { output in
            password.withUnsafeBytes { passwordBytes in
                salt.withUnsafeBytes { saltBytes in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBytes.bindMemory(to: Int8.self).baseAddress,
                        passwordCount,
                        saltBytes.bindMemory(to: UInt8.self).baseAddress,
                        saltCount,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        UInt32(iterations),
                        output.bindMemory(to: UInt8.self).baseAddress,
                        keyLength
                    )
                }
            }
        }

        guard status == kCCSuccess else {
            throw GSAError.malformedResponse("PBKDF2 failed (\(status))")
        }
        return Data(derived)
    }

    static func aes256CBCDecrypt(_ ciphertext: Data, key: Data, iv: Data) throws -> Data {
        guard key.count == kCCKeySizeAES256, iv.count == kCCBlockSizeAES128 else {
            throw GSAError.malformedResponse("invalid AES-CBC parameters")
        }

        var output = [UInt8](repeating: 0, count: ciphertext.count + kCCBlockSizeAES128)
        var moved = 0
        let outputCount = output.count
        let ciphertextCount = ciphertext.count
        let keyCount = key.count
        let status = output.withUnsafeMutableBytes { outputBytes in
            ciphertext.withUnsafeBytes { ciphertextBytes in
                key.withUnsafeBytes { keyBytes in
                    iv.withUnsafeBytes { ivBytes in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyBytes.baseAddress, keyCount,
                            ivBytes.baseAddress,
                            ciphertextBytes.baseAddress, ciphertextCount,
                            outputBytes.baseAddress, outputCount,
                            &moved
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else {
            throw GSAError.malformedResponse("AES-CBC decrypt failed (\(status))")
        }
        return Data(output.prefix(moved))
    }
}
