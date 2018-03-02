// Copyright © 2017-2018 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import Foundation

/// Manages directories of key and wallet files and presents them as accounts.
public final class KeyStore {
    /// The key file directory.
    public let keyDirectory: URL

    /// The wallet file directory.
    public let walletDirectory: URL

    /// Dictionary of accounts by address.
    private var accountsByAddress = [Address: Account]()

    /// Dictionary of keys by address.
    private var keysByAddress = [Address: KeystoreKey]()

    /// Dictionary of wallets by address.
    private var walletsByAddress = [Address: WalletDescriptor]()

    /// Creates a `KeyStore` for the given directory.
    public init(keyDirectory: URL, walletDirectory: URL) throws {
        self.keyDirectory = keyDirectory
        self.walletDirectory = walletDirectory
        try load()
    }

    private func load() throws {
        let fileManager = FileManager.default
        try? fileManager.createDirectory(at: keyDirectory, withIntermediateDirectories: true, attributes: nil)
        try? fileManager.createDirectory(at: walletDirectory, withIntermediateDirectories: true, attributes: nil)

        let accountURLs = try fileManager.contentsOfDirectory(at: keyDirectory, includingPropertiesForKeys: [], options: [.skipsHiddenFiles])
        for url in accountURLs {
            do {
                let key = try KeystoreKey(contentsOf: url)
                keysByAddress[key.address] = key
                let account = Account(address: key.address, type: .encryptedKey, url: url)
                accountsByAddress[key.address] = account
            } catch {
                // Ignore invalid keys
            }
        }

        let walletURLs = try fileManager.contentsOfDirectory(at: walletDirectory, includingPropertiesForKeys: [], options: [.skipsHiddenFiles])
        for url in walletURLs {
            do {
                let wd = try WalletDescriptor(contentsOf: url)
                walletsByAddress[wd.address] = wd
                let account = Account(address: wd.address, type: .hierarchicalDeterministicWallet, url: url)
                accountsByAddress[wd.address] = account
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

    /// Retrieves a wallet for the given address, if it exists.
    public func wallet(for address: Address) -> WalletDescriptor? {
        return walletsByAddress[address]
    }

    /// Creates a new account.
    public func createAccount(password: String, type: AccountType) throws -> Account {
        switch type {
        case .encryptedKey:
            return try createKey(password: password)
        case .hierarchicalDeterministicWallet:
            return try createWallet(password: password)
        }
    }

    func createKey(password: String) throws -> Account {
        let key = try KeystoreKey(password: password)
        keysByAddress[key.address] = key

        let url = makeAccountURL(for: key.address, type: .encryptedKey)
        let account = Account(address: key.address, type: .encryptedKey, url: url)
        try save(account: account, in: keyDirectory)
        accountsByAddress[key.address] = account
        return account
    }

    func createWallet(password: String) throws -> Account {
        let mnemonic = Mnemonic.generate(strength: 256)
        let wallet = Wallet(mnemonic: mnemonic, password: password)
        let address = wallet.getKey(at: 0).address
        let url = makeAccountURL(for: address, type: .hierarchicalDeterministicWallet)
        let wd = WalletDescriptor(mnemonic: mnemonic, address: address)
        walletsByAddress[address] = wd

        let account = Account(address: address, type: .hierarchicalDeterministicWallet, url: url)
        try save(account: account, in: keyDirectory)
        accountsByAddress[address] = account

        return account
    }

    /// Imports an encrypted JSON key.
    ///
    /// - Parameters:
    ///   - key: key to import
    ///   - password: key password
    ///   - newPassword: password to use for the imported key
    /// - Returns: new account
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

        let url = makeAccountURL(for: key.address, type: .encryptedKey)
        let account = Account(address: newKey.address, type: .encryptedKey, url: url)
        try save(account: account, in: keyDirectory)
        accountsByAddress[newKey.address] = account

        return account
    }

    /// Imports a wallet.
    ///
    /// - Parameters:
    ///   - mnemonic: wallet's mnemonic phrase
    ///   - password: password
    /// - Returns: new account
    public func `import`(mnemonic: String, password: String) throws -> Account {
        let wallet = Wallet(mnemonic: mnemonic, password: password)
        let address = wallet.getKey(at: 0).address
        if self.account(for: address) != nil {
            throw Error.accountAlreadyExists
        }

        let wd = WalletDescriptor(mnemonic: mnemonic, address: address)
        walletsByAddress[address] = wd

        let url = makeAccountURL(for: address, type: .hierarchicalDeterministicWallet)
        let account = Account(address: address, type: .hierarchicalDeterministicWallet, url: url)
        try save(account: account, in: keyDirectory)
        accountsByAddress[address] = account

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
        switch account.type {
        case .encryptedKey:
            guard let key = keysByAddress[account.address] else {
                fatalError("Missing account key")
            }

            var privateKey = try key.decrypt(password: password)
            defer {
                privateKey.resetBytes(in: 0..<privateKey.count)
            }

            keysByAddress[account.address] = nil
        case .hierarchicalDeterministicWallet:
            guard let wd = walletsByAddress[account.address] else {
                fatalError("Missing account wallet")
            }

            let wallet = Wallet(mnemonic: wd.mnemonic, password: password)
            if wallet.getKey(at: 0).address != wd.address {
                // Wrong password
                return
            }

            walletsByAddress[wd.address] = nil
        }

        try FileManager.default.removeItem(at: account.url)
        accountsByAddress[account.address] = nil
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
        switch account.type {
        case .encryptedKey:
            guard let key = keysByAddress[account.address] else {
                throw KeyStore.Error.accountNotFound
            }
            return try key.sign(hash: data, password: password)
        case .hierarchicalDeterministicWallet:
            guard let wd = walletsByAddress[account.address] else {
                throw KeyStore.Error.accountNotFound
            }
            let wallet = Wallet(mnemonic: wd.mnemonic, password: password)
            return try wallet.getKey(at: 0).sign(hash: data)
        }
    }

    /// Signs an array of hashes with the given password.
    ///
    /// - Parameters:
    ///   - hashes: array of hashes to sign
    ///   - account: account to use for signing
    ///   - password: key password
    /// - Returns: array of signatures
    /// - Throws: `DecryptError` or `Secp256k1Error` or `KeyStore.Error`
    public func signHashes(_ data: [Data], account: Account, password: String) throws -> [Data] {
        switch account.type {
        case .encryptedKey:
            guard let key = keysByAddress[account.address] else {
                throw KeyStore.Error.accountNotFound
            }
            return try key.signHashes(hashes: data, password: password)
        case .hierarchicalDeterministicWallet:
            guard let wd = walletsByAddress[account.address] else {
                throw KeyStore.Error.accountNotFound
            }
            var arrayOfSignatures = [Data]()
            let wallet = Wallet(mnemonic: wd.mnemonic, password: password)
            let key = try wallet.getKey(at: 0)
            for i in 0...data.count - 1 {
                let signature = try key.sign(hash: data[i])
                arrayOfSignatures.append(signature)
            }
            return arrayOfSignatures
        }
    }

    // MARK: Helpers

    private func makeAccountURL(for address: Address, type: AccountType) -> URL {
        switch type {
        case .encryptedKey:
            return keyDirectory.appendingPathComponent(generateFileName(address: address))
        case .hierarchicalDeterministicWallet:
            return walletDirectory.appendingPathComponent(generateFileName(address: address))
        }
    }

    /// Saves the account to the given directory.
    private func save(account: Account, in directory: URL) throws {
        switch account.type {
        case .encryptedKey:
            guard let key = keysByAddress[account.address] else {
                fatalError("Missing account key")
            }
            try save(key: key, to: account.url)
        case .hierarchicalDeterministicWallet:
            guard let wallet = walletsByAddress[account.address] else {
                fatalError("Missing account wallet")
            }
            try save(wallet: wallet, to: account.url)
        }
    }

    /// Generates a unique file name for an address.
    func generateFileName(address: Address, date: Date = Date(), timeZone: TimeZone = .current) -> String {
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

    private func save(key: KeystoreKey, to url: URL) throws {
        let json = try JSONEncoder().encode(key)
        try json.write(to: url, options: [.atomicWrite])
    }

    private func save(wallet: WalletDescriptor, to url: URL) throws {
        let json = try JSONEncoder().encode(wallet)
        try json.write(to: url, options: [.atomicWrite])
    }
}
