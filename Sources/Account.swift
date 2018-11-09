// Copyright © 2017-2018 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import Foundation
import TrustCore

/// Account represents a specific address in a wallet.
public final class Account: Codable, Hashable {
    /// Wallet this account belongs to.
    public weak var wallet: Wallet?

    /// Account public address
    public var address: Address

    /// Account derivation path, only relevant for HD wallets.
    public let derivationPath: DerivationPath

    /// Account Extended Public Key
    public var extendedPublicKey: String?

    /// Coin this account is for.
    public var coin: Int {
        return derivationPath.coinType
    }

    /// Creates a new `Account`.
    ///
    /// - Parameters:
    ///   - wallet: wallet that owns the account
    ///   - address: account's public address
    ///   - derivationPath: HD derivation path, only relevant for HD wallets
    public init(wallet: Wallet?, address: Address, derivationPath: DerivationPath) {
        self.wallet = wallet
        self.address = address
        self.derivationPath = derivationPath
    }

    /// Signs a hash with the given password.
    ///
    /// - Parameters:
    ///   - hash: hash to sign
    ///   - password: key password
    /// - Returns: signature
    /// - Throws: `DecryptError` or `Secp256k1Error`
    public func sign(hash: Data, password: String) throws -> Data {
        let key = try privateKey(password: password)
        return Crypto.sign(hash: hash, privateKey: key.data)
    }

    /// Signs multiple hashes with the given password.
    ///
    /// - Parameters:
    ///   - hashes: array of hashes to sign
    ///   - password: key password
    /// - Returns: [signature]
    /// - Throws: `DecryptError` or `Secp256k1Error`
    public func signHashes(_ hashes: [Data], password: String) throws -> [Data] {
        let key = try privateKey(password: password)
        return hashes.map({ Crypto.sign(hash: $0, privateKey: key.data) })
    }

    // MARK: PrivateKey

    public func privateKey(password: String) throws -> PrivateKey {
        guard let wallet = wallet else {
            fatalError("Wallet no longer exists")
        }
        let key = wallet.key
        switch key.type {
        case .encryptedKey:
            var key = try key.decrypt(password: password)
            defer {
                // Clear memory after signing
                key.resetBytes(in: 0..<key.count)
            }
            return PrivateKey(data: key)!
        case .hierarchicalDeterministicWallet:
            return try privateKey(at: derivationPath, password: password)
        }
    }

    public func privateKey(at path: DerivationPath, password: String) throws -> PrivateKey {
        return try privateKeys(at: [derivationPath], password: password).first!
    }

    public func privateKeys(at paths: [DerivationPath], password: String) throws -> [PrivateKey] {
        guard let wallet = wallet else {
            fatalError("Wallet no longer exists")
        }
        guard case .hierarchicalDeterministicWallet = wallet.key.type else {
            fatalError("Not HD wallet")
        }
        let hdWallet = try getHDWallet(key: wallet.key, password: password)
        return paths.map { hdWallet.getKey(at: $0) }
    }

    private func getHDWallet(key: KeystoreKey, password: String) throws -> HDWallet {
        guard var mnemonic = String(data: try key.decrypt(password: password), encoding: .ascii) else {
            throw DecryptError.invalidPassword
        }
        defer {
            // Clear memory after signing
            mnemonic.clear()
        }
        let wallet = HDWallet(mnemonic: mnemonic, passphrase: key.passphrase)
        return wallet
    }

    // MARK: Hashable

    public var hashValue: Int {
        return address.data.hashValue
    }

    public static func == (lhs: Account, rhs: Account) -> Bool {
        return lhs.address.data == rhs.address.data
    }

    // MARK: Codable

    enum CodingKeys: String, CodingKey {
        case addressData
        case derivationPath
        case extendedPublicKey
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        derivationPath = try container.decode(DerivationPath.self, forKey: .derivationPath)
        let addressData = try container.decode(Data.self, forKey: .addressData)
        self.extendedPublicKey = try container.decodeIfPresent(String.self, forKey: .extendedPublicKey)

        guard let slip = SLIP.CoinType(rawValue: derivationPath.coinType) else {
            throw DecryptError.unsupportedCoin
        }
        let bc = blockchain(coin: slip)

        guard let address = bc.address(data: addressData) else {
            throw DecodingError.dataCorruptedError(forKey: .addressData, in: container, debugDescription: "Invalid address")
        }

        self.address = address
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(address.data, forKey: .addressData)
        try container.encode(derivationPath, forKey: .derivationPath)
        try container.encode(extendedPublicKey, forKey: .extendedPublicKey)
    }
}
