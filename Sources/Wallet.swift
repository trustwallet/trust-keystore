// Copyright © 2017-2018 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import Foundation
import TrustCore

/// Coin wallet.
public final class Wallet: Hashable {
    /// Unique wallet identifier.
    public let identifier: String

    /// URL for the key file on disk.
    public var keyURL: URL

    /// Encrypted wallet key
    public var key: KeystoreKey

    /// Wallet type.
    public var type: WalletType {
        return key.type
    }

    /// Wallet accounts.
    public internal(set) var accounts = [Account]()

    /// Creates a `Wallet` from an encrypted key.
    public init(keyURL: URL, key: KeystoreKey) {
        identifier = keyURL.lastPathComponent
        self.keyURL = keyURL
        self.key = key
    }

    /// Returns the only account for non HD-wallets.
    ///
    /// - Parameters:
    ///   - password: wallet encryption password
    ///   - type: blockchain type
    /// - Returns: the account
    /// - Throws: `WalletError.invalidKeyType` if this is an HD wallet `DecryptError.invalidPassword` if the
    ///           password is incorrect.
    public func getAccount(password: String, coin: SLIP.CoinType) throws -> Account {
        guard key.type == .encryptedKey else {
            throw WalletError.invalidKeyType
        }

        if let account = accounts.first {
            return account
        }

        let bc = blockchain(coin: coin)
        guard let privateKey = PrivateKey(data: try key.decrypt(password: password)) else {
            throw DecryptError.invalidPassword
        }
        let publicKey = privateKey.publicKey()
        let address = bc.address(for: publicKey)

        let account = Account(wallet: self, address: address, derivationPath: bc.derivationPath(at: 0))
        account.wallet = self
        accounts.append(account)
        return account
    }

    /// Returns accounts for specific derivation paths.
    ///
    /// - Parameters:
    ///   - coin: coin this account is for
    ///   - derivationPaths: array of HD derivation paths
    ///   - password: wallet encryption password
    /// - Returns: the accounts
    /// - Throws: `WalletError.invalidKeyType` if this is not an HD wallet `DecryptError.invalidPassword` if the
    ///           password is incorrect.
    public func getAccounts(derivationPaths: [DerivationPath], password: String) throws -> [Account] {
        guard key.type == .hierarchicalDeterministicWallet else {
            throw WalletError.invalidKeyType
        }

        guard var mnemonic = String(data: try key.decrypt(password: password), encoding: .ascii) else {
            throw DecryptError.invalidPassword
        }
        defer {
            mnemonic.clear()
        }

        var accounts = [Account]()
        let wallet = HDWallet(mnemonic: mnemonic, passphrase: key.passphrase)
        for derivationPath in derivationPaths {
            guard let slip = SLIP.CoinType(rawValue: derivationPath.coinType) else { break }
            let account = getAccount(wallet: wallet, coin: slip, derivationPath: derivationPath)
            accounts.append(account)
        }

        return accounts
    }

    private func getAccount(wallet: HDWallet, coin: SLIP.CoinType, derivationPath: DerivationPath) -> Account {
        let bc = blockchain(coin: coin)
        let publicKey = wallet.getKey(at: derivationPath).publicKey()
        let address = bc.address(for: publicKey)

        if let account = accounts.first(where: { $0.derivationPath == derivationPath }) {
            return account
        }

        let account = Account(wallet: self, address: address, derivationPath: derivationPath)
        account.wallet = self
        if let version = bc.xpubVersion,
            account.extendedPublicKey == nil {
            account.extendedPublicKey = wallet.getExtendedPubKey(for: bc.coinPurpose, coin: coin, version: version)
        }
        accounts.append(account)
        return account
    }

    public var hashValue: Int {
        return identifier.hashValue
    }

    public static func == (lhs: Wallet, rhs: Wallet) -> Bool {
        return lhs.identifier == rhs.identifier
    }
}

/// Support account types.
public enum WalletType {
    case encryptedKey
    case hierarchicalDeterministicWallet
}

public enum WalletError: LocalizedError {
    case invalidKeyType
}
