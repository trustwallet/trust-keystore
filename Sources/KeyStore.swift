// Copyright © 2017 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import Foundation

/// Manages a directory of key files and presents them as accounts.
public final class KeyStore {
    /// The key file directory.
    public let keydir: URL

    /// Dictionary of accounts by address.
    private var accountsByAddress = [Address: Account]()

    /// Dictionary of keys by address.
    private var keysByAddress = [Address: KeystoreKey]()

    /// Creates a `KeyStore` for the given directory.
    public init(keydir: URL) throws {
        self.keydir = keydir
        try load()
    }

    private func load() throws {
        let fileManager = FileManager.default
        try? fileManager.createDirectory(at: keydir, withIntermediateDirectories: true, attributes: nil)

        let accountURLs = try fileManager.contentsOfDirectory(at: keydir, includingPropertiesForKeys: [], options: [.skipsHiddenFiles])
        for url in accountURLs {
            do {
                let key = try KeystoreKey(contentsOf: url)
                keysByAddress[key.address] = key
                let account = Account(address: key.address, url: url)
                accountsByAddress[key.address] = account
            } catch {
                // Ignore invalid keys
            }
        }
    }

    /// List of accounts.
    public var accounts: [Account] {
        return Array(accountsByAddress.values)
    }

    /// Retrieves an account for the given address, if it exists.
    public func account(for address: Address) -> Account? {
        return accountsByAddress[address]
    }

    /// Retrieves a key for the given address, if it exists.
    public func key(for address: Address) -> KeystoreKey? {
        return keysByAddress[address]
    }

    /// Creates a new account.
    @available(iOS 10.0, *)
    public func createAccount(password: String) throws -> Account {
        let key = try KeystoreKey(password: password)
        keysByAddress[key.address] = key

        let url = makeAccountURL(for: key)
        let account = Account(address: key.address, url: url)
        try save(account: account, in: keydir)
        accountsByAddress[key.address] = account
        return account
    }

    /// Imports an encrypted JSON key.
    ///
    /// - Parameters:
    ///   - key: key to import
    ///   - password: key password
    ///   - newPassword: password to use for the imported key
    public func `import`(json: Data, password: String, newPassword: String) throws -> Account {
        let key = try JSONDecoder().decode(KeystoreKey.self, from: json)
        if self.account(for: key.address) != nil {
            throw Error.accountAlreadyExists
        }

        var privateKey = try key.decrypt(password: password)
        defer {
            privateKey.resetBytes(in: 0..<privateKey.count)
        }

        let newKey = try KeystoreKey(password: newPassword, key: privateKey)
        keysByAddress[newKey.address] = newKey

        let url = makeAccountURL(for: key)
        let account = Account(address: newKey.address, url: url)
        try save(account: account, in: keydir)
        accountsByAddress[newKey.address] = account

        return account
    }

    /// Exports an account as JSON data.
    ///
    /// - Parameters:
    ///   - account: account to export
    ///   - password: account password
    ///   - newPassword: password to use for exported key
    /// - Returns: encrypted JSON key
    public func export(account: Account, password: String, newPassword: String) throws -> Data {
        guard let key = keysByAddress[account.address] else {
            fatalError("Missing account key")
        }

        var privateKey = try key.decrypt(password: password)
        defer {
            privateKey.resetBytes(in: 0..<privateKey.count)
        }

        let newKey = try KeystoreKey(password: newPassword, key: privateKey)
        return try JSONEncoder().encode(newKey)
    }

    /// Exports an account as private key data.
    ///
    /// - Parameters:
    ///   - account: account to export
    ///   - password: account password
    /// - Returns: private key data

    public func exportPrivateKey(account: Account, password: String) throws -> Data {
        guard let key = keysByAddress[account.address] else {
            fatalError("Missing account key")
        }
        return try key.decrypt(password: password)
    }

    /// Updates the password of an existing account.
    ///
    /// - Parameters:
    ///   - account: account to update
    ///   - password: current password
    ///   - newPassword: new password
    public func update(account: Account, password: String, newPassword: String) throws {
        guard let key = keysByAddress[account.address] else {
            fatalError("Missing account key")
        }

        var privateKey = try key.decrypt(password: password)
        defer {
            privateKey.resetBytes(in: 0..<privateKey.count)
        }

        let newKey = try KeystoreKey(password: newPassword, key: privateKey)
        keysByAddress[newKey.address] = newKey
    }

    /// Deletes an account including its key if the password is correct.
    public func delete(account: Account, password: String) throws {
        guard let key = keysByAddress[account.address] else {
            fatalError("Missing account key")
        }

        var privateKey = try key.decrypt(password: password)
        defer {
            privateKey.resetBytes(in: 0..<privateKey.count)
        }

        try FileManager.default.removeItem(at: account.url)
        accountsByAddress[account.address] = nil
        keysByAddress[account.address] = nil
    }

    /// Calculates a ECDSA signature for the give hash.
    ///
    /// - Parameters:
    ///   - data: hash to sign
    ///   - account: account to use for signing
    ///   - password: account password
    /// - Returns: signature
    /// - Throws: `DecryptError`, `Secp256k1Error`, or `KeyStore.Error`
    public func signHash(_ data: Data, account: Account, password: String) throws -> Data {
        guard let key = keysByAddress[account.address] else {
            throw KeyStore.Error.accountNotFound
        }
        return try key.sign(hash: data, password: password)
    }

    // MARK: Helpers

    private func makeAccountURL(for key: KeystoreKey) -> URL {
        return keydir.appendingPathComponent(key.generateFileName())
    }

    /// Saves the account to the given directory.
    private func save(account: Account, in directory: URL) throws {
        guard let key = keysByAddress[account.address] else {
            fatalError("Missing account key")
        }
        try save(key: key, to: account.url)
    }

    private func save(key: KeystoreKey, to url: URL) throws {
        let json = try JSONEncoder().encode(key)
        try json.write(to: url, options: [.atomicWrite])
    }
}
