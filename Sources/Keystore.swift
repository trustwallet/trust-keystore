// Copyright © 2017 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import CryptoSwift
import Foundation
import secp256k1

/// Keystore wallet definition.
public struct Keystore: Codable {
    /// Ethereum address, optional.
    public var address: String?

    /// Wallet UUID, optional.
    public var id: String?

    /// Key header with encrypted private key and crypto parameters.
    public var crypto: KeyHeader

    /// Keystore version, must be 3.
    public var version = 3

    /// Initializes a `Keystore` with a crypto header.
    public init(header: KeyHeader) {
        self.crypto = header
    }

    /// Initializes a `Keystore` from a JSON wallet.
    public init(contentsOf url: URL) throws {
        let data = try Data(contentsOf: url)
        self = try JSONDecoder().decode(Keystore.self, from: data)
    }

    /// Initializes a `Keystore` by encrypting a private key with a password.
    public init(password: String, key: Data) throws {
        id = UUID().uuidString.lowercased()

        let cipherParams = CipherParams()
        let kdfParams = ScryptParams()

        let scrypt = Scrypt(params: kdfParams)
        let derivedKey = try scrypt.calculate(password: password)

        let encryptionKey = derivedKey[0...15]
        let aecCipher = try AES(key: encryptionKey.bytes, blockMode: .CBC(iv: cipherParams.iv.bytes), padding: .noPadding)

        let encryptedKey = try aecCipher.encrypt(key.bytes)
        let prefix = derivedKey[(derivedKey.count - 16) ..< derivedKey.count]
        let mac = Keystore.computeMAC(prefix: prefix, key: Data(bytes: encryptedKey))

        crypto = KeyHeader(cipherText: Data(bytes: encryptedKey), cipherParams: cipherParams, kdfParams: kdfParams, mac: mac)

        let pubKey = Secp256k1.shared.pubicKey(from: key)
        address = Keystore.decodeAddress(from: pubKey).hexString
    }

    /// Decodes an Ethereum address from a public key.
    static func decodeAddress(from publicKey: Data) -> Data {
        precondition(publicKey.count == 65, "Expect 64-byte public key")
        precondition(publicKey[0] == 4, "Invalid public key")
        let sha3 = publicKey[1...].sha3(.keccak256)
        return sha3[12..<32]
    }

    /// Decrypts the keystore and returns the private key.
    public func decrypt(password: String) throws -> Data {
        let derivedKey: Data
        switch crypto.kdf {
        case "scrypt":
            let scrypt = Scrypt(params: crypto.kdfParams)
            derivedKey = try scrypt.calculate(password: password)
        default:
            throw DecryptError.unsupportedKDF
        }

        let mac = Keystore.computeMAC(prefix: derivedKey[derivedKey.count - 16 ..< derivedKey.count], key: crypto.cipherText)
        if mac != crypto.mac {
            throw DecryptError.invalidPassword
        }

        let decryptionKey = derivedKey[0...15]
        let decryptedPK: [UInt8]
        switch crypto.cipher {
        case "aes-128-ctr":
            let aesCipher = try AES(key: decryptionKey.bytes, blockMode: .CTR(iv: crypto.cipherParams.iv.bytes), padding: .noPadding)
            decryptedPK = try aesCipher.decrypt(crypto.cipherText.bytes)
        case "aes-128-cbc":
            let aesCipher = try AES(key: decryptionKey.bytes, blockMode: .CBC(iv: crypto.cipherParams.iv.bytes), padding: .noPadding)
            decryptedPK = try aesCipher.decrypt(crypto.cipherText.bytes)
        default:
            throw DecryptError.unsupportedCipher
        }

        return Data(bytes: decryptedPK)
    }

    private static func computeMAC(prefix: Data, key: Data) -> Data {
        var data = Data(capacity: prefix.count + key.count)
        data.append(prefix)
        data.append(key)
        return data.sha3(.keccak256)
    }
}

public enum DecryptError: Error {
    case unsupportedKDF
    case unsupportedCipher
    case invalidCipher
    case invalidPassword
}
