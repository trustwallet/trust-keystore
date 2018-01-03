// Copyright © 2017 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import CryptoSwift
import Foundation
import secp256k1

/// Key definition.
public struct Key: Codable {
    /// Ethereum address, optional.
    public var address: String?

    /// Wallet UUID, optional.
    public var id: String?

    /// Key header with encrypted private key and crypto parameters.
    public var crypto: KeyHeader

    /// Key version, must be 3.
    public var version = 3

    /// Initializes a `Key` with a crypto header.
    public init(header: KeyHeader) {
        self.crypto = header
    }

    /// Initializes a `Key` from a JSON wallet.
    public init(contentsOf url: URL) throws {
        let data = try Data(contentsOf: url)
        self = try JSONDecoder().decode(Key.self, from: data)
    }

    /// Initializes a `Key` by encrypting a private key with a password.
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
        let mac = Key.computeMAC(prefix: prefix, key: Data(bytes: encryptedKey))

        crypto = KeyHeader(cipherText: Data(bytes: encryptedKey), cipherParams: cipherParams, kdfParams: kdfParams, mac: mac)

        let pubKey = Secp256k1.shared.pubicKey(from: key)
        address = Key.decodeAddress(from: pubKey).hexString
    }

    /// Decodes an Ethereum address from a public key.
    static func decodeAddress(from publicKey: Data) -> Data {
        precondition(publicKey.count == 65, "Expect 64-byte public key")
        precondition(publicKey[0] == 4, "Invalid public key")
        let sha3 = publicKey[1...].sha3(.keccak256)
        return sha3[12..<32]
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

        let mac = Key.computeMAC(prefix: derivedKey[derivedKey.count - 16 ..< derivedKey.count], key: crypto.cipherText)
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
        return "UTC--\(filenameTimestamp(for: date, in: timeZone))--\(address ?? "")"
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
