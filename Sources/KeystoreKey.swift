// Copyright © 2017-2018 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import CryptoSwift
import Foundation
import secp256k1_ios
import Security

/// Key definition.
public struct KeystoreKey {
    /// Ethereum address.
    public var address: Address

    /// Wallet UUID, optional.
    public var id: String?

    /// Key header with encrypted private key and crypto parameters.
    public var crypto: KeystoreKeyHeader

    /// Key version, must be 3.
    public var version = 3

    /// Creates a new `Key` with a password.
    @available(iOS 10.0, *)
    public init(password: String) throws {
        let privateAttributes: [String: Any] = [
            kSecAttrIsExtractable as String: true,
        ]
        let parameters: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: privateAttributes,
        ]

        var pubKey: SecKey?
        var privKey: SecKey?
        let status = SecKeyGeneratePair(parameters as CFDictionary, &pubKey, &privKey)
        guard let privateKey = privKey, status == noErr else {
            fatalError("Failed to generate key pair")
        }

        guard let keyRepresentation = SecKeyCopyExternalRepresentation(privateKey, nil) as Data? else {
            fatalError("Failed to extract new private key")
        }
        let key = keyRepresentation[(keyRepresentation.count - 32)...]
        try self.init(password: password, key: key)
    }

    /// Initializes a `Key` from a JSON wallet.
    public init(contentsOf url: URL) throws {
        let data = try Data(contentsOf: url)
        self = try JSONDecoder().decode(KeystoreKey.self, from: data)
    }

    /// Initializes a `Key` by encrypting a private key with a password.
    public init(password: String, key: Data) throws {
        id = UUID().uuidString.lowercased()

        let cipherParams = CipherParams()
        let kdfParams = ScryptParams()

        let scrypt = Scrypt(params: kdfParams)
        let derivedKey = try scrypt.calculate(password: password)

        let encryptionKey = derivedKey[0...15]
        let aecCipher = try AES(key: encryptionKey.bytes, blockMode: .CTR(iv: cipherParams.iv.bytes), padding: .noPadding)

        let encryptedKey = try aecCipher.encrypt(key.bytes)
        let prefix = derivedKey[(derivedKey.count - 16) ..< derivedKey.count]
        let mac = KeystoreKey.computeMAC(prefix: prefix, key: Data(bytes: encryptedKey))

        crypto = KeystoreKeyHeader(cipherText: Data(bytes: encryptedKey), cipherParams: cipherParams, kdfParams: kdfParams, mac: mac)

        let pubKey = Secp256k1.shared.pubicKey(from: key)
        address = KeystoreKey.decodeAddress(from: pubKey)
    }

    /// Decodes an Ethereum address from a public key.
    static func decodeAddress(from publicKey: Data) -> Address {
        precondition(publicKey.count == 65, "Expect 64-byte public key")
        precondition(publicKey[0] == 4, "Invalid public key")
        let sha3 = publicKey[1...].sha3(.keccak256)
        return Address(data: sha3[12..<32])
    }

    /// Decrypts the key and returns the private key.
    public func decrypt(password: String) throws -> Data {
        let derivedKey: Data
        switch crypto.kdf {
        case "scrypt":
            let scrypt = Scrypt(params: crypto.kdfParams)
            derivedKey = try scrypt.calculate(password: password)
        default:
            throw DecryptError.unsupportedKDF
        }

        let mac = KeystoreKey.computeMAC(prefix: derivedKey[derivedKey.count - 16 ..< derivedKey.count], key: crypto.cipherText)
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

    /// Signs a hash with the given password.
    ///
    /// - Parameters:
    ///   - hash: hash to sign
    ///   - password: key password
    /// - Returns: signature
    /// - Throws: `DecryptError` or `Secp256k1Error`
    public func sign(hash: Data, password: String) throws -> Data {
        let key = try decrypt(password: password)
        return try Secp256k1.shared.sign(hash: hash, privateKey: key)
    }

    /// Generates a unique file name for this key.
    public func generateFileName(date: Date = Date(), timeZone: TimeZone = .current) -> String {
        // keyFileName implements the naming convention for keyfiles:
        // UTC--<created_at UTC ISO8601>-<address hex>
        return "UTC--\(filenameTimestamp(for: date, in: timeZone))--\(address.data.hexString)"
    }

    private func filenameTimestamp(for date: Date, in timeZone: TimeZone = .current) -> String {
        var tz = ""
        let offset = timeZone.secondsFromGMT()
        if offset == 0 {
            tz = "Z"
        } else {
            tz = String(format: "%03d00", offset/60)
        }

        let components = Calendar(identifier: .iso8601).dateComponents(in: timeZone, from: date)
        return String(format: "%04d-%02d-%02dT%02d-%02d-%02d.%09d%@", components.year!, components.month!, components.day!, components.hour!, components.minute!, components.second!, components.nanosecond!, tz)
    }
}

public enum DecryptError: Error {
    case unsupportedKDF
    case unsupportedCipher
    case invalidCipher
    case invalidPassword
}

extension KeystoreKey: Codable {
    enum CodingKeys: String, CodingKey {
        case address
        case id
        case crypto
        case version
    }

    enum UppercaseCodingKeys: String, CodingKey {
        case crypto = "Crypto"
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let altValues = try decoder.container(keyedBy: UppercaseCodingKeys.self)
        address = Address(data: try values.decodeHexString(forKey: .address))
        id = try values.decode(String.self, forKey: .id)
        if let crypto = try? values.decode(KeystoreKeyHeader.self, forKey: .crypto) {
            self.crypto = crypto
        } else {
            // Workaround for myEtherWallet files
            self.crypto = try altValues.decode(KeystoreKeyHeader.self, forKey: .crypto)
        }
        version = try values.decode(Int.self, forKey: .version)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(address.description, forKey: .address)
        try container.encode(id, forKey: .id)
        try container.encode(crypto, forKey: .crypto)
        try container.encode(version, forKey: .version)
    }
}
