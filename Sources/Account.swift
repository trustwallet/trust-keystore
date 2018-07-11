// Copyright © 2017-2018 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import Foundation
import TrustCore

/// Account represents a specific address in a wallet.
public final class Account: Hashable {
    /// Wallet this account belongs to.
    weak var wallet: Wallet?

    /// Account public address
    public var address: Address

    /// Account derivation path, only relevant for HD wallets.
    public let derivationPath: DerivationPath

    /// Blockchain this account is for.
    public var blockchain: Blockchain {
        return address.blockchain
    }

    /// Creates a new `Account`.
    ///
    /// - Parameters:
    ///   - wallet: wallet that owns the account
    ///   - address: account's public address
    ///   - derivationPath: HD derivation path, only relevant for HD wallets
    public init(wallet: Wallet, address: Address, derivationPath: DerivationPath) {
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
            guard var mnemonic = String(data: try key.decrypt(password: password), encoding: .ascii) else {
                throw DecryptError.invalidPassword
            }
            defer {
                // Clear memory after signing
                mnemonic.clear()
            }
            let wallet = HDWallet(mnemonic: mnemonic, passphrase: key.passphrase)
            return wallet.getKey(at: derivationPath)
        }
    }

    // MARK: Hashable

    public var hashValue: Int {
        return address.data.hashValue
    }

    public static func == (lhs: Account, rhs: Account) -> Bool {
        return lhs.address.data == rhs.address.data
    }
}
