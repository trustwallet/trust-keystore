// Copyright © 2017 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import Foundation

public final class WalletStore {
    /// The wallet file directory.
    public let directory: URL

    /// Dictionary of wallets by address.
    private var walletsByAddress = [Address: WalletDescriptor]()

    /// Creates a `WalletStore` for the given directory.
    public init(directory: URL) throws {
        self.directory = directory
        try load()
    }

    private func load() throws {
        let fileManager = FileManager.default
        try? fileManager.createDirectory(at: directory, withIntermediateDirectories: true, attributes: nil)

        let walletURLs = try fileManager.contentsOfDirectory(at: directory, includingPropertiesForKeys: [], options: [.skipsHiddenFiles])
        for url in walletURLs {
            do {
                let wd = try WalletDescriptor(contentsOf: url)
                walletsByAddress[wd.address] = wd
            } catch {
                // Ignore invalid keys
            }
        }
    }

    /// List of wallets.
    public var wallets: [WalletDescriptor] {
        return Array(walletsByAddress.values)
    }

    /// Retrieves a wallet for the given address, if it exists.
    public func wallet(for address: Address) -> WalletDescriptor? {
        return walletsByAddress[address]
    }

    /// Creates a new wallet.
    public func createWallet(password: String, name: String? = nil) throws -> WalletDescriptor {
        let mnemonic = Mnemonic.generate(strength: 256)
        let wallet = Wallet(mnemonic: mnemonic, password: password)
        let address = wallet.getKey(at: 0).address
        let url = directory.appendingPathComponent(WalletDescriptor.generateFileName(address: address))
        let wd = WalletDescriptor(mnemonic: mnemonic, name: name, address: address, url: url)
        walletsByAddress[address] = wd

        let json = try JSONEncoder().encode(wd)
        try json.write(to: url, options: [.atomicWrite])

        return wd
    }

    /// Imports a wallet.
    public func `import`(mnemonic: String, password: String, name: String? = nil) throws -> WalletDescriptor {
        let wallet = Wallet(mnemonic: mnemonic, password: password)
        let address = wallet.getKey(at: 0).address
        let url = directory.appendingPathComponent(WalletDescriptor.generateFileName(address: address))
        let wd = WalletDescriptor(mnemonic: mnemonic, name: name, address: address, url: url)
        walletsByAddress[address] = wd

        let json = try JSONEncoder().encode(wd)
        try json.write(to: url, options: [.atomicWrite])

        return wd
    }

    /// Deletes a wallet if the password is correct.
    public func delete(wallet wd: WalletDescriptor, password: String) throws {
        let wallet = Wallet(mnemonic: wd.mnemonic, password: password)
        if wallet.getKey(at: 0).address != wd.address {
            // Wrong password
            return
        }

        try FileManager.default.removeItem(at: wd.url)
        walletsByAddress[wd.address] = nil
    }

    /// Calculates a ECDSA signature for the give hash.
    ///
    /// - Parameters:
    ///   - data: hash to sign
    ///   - wallet: wallet to use for signing
    ///   - password: wallet password
    /// - Returns: signature
    /// - Throws: `DecryptError`, `Secp256k1Error`, or `KeyStore.Error`
    public func signHash(_ data: Data, wallet wd: WalletDescriptor, password: String) throws -> Data {
        let wallet = Wallet(mnemonic: wd.mnemonic, password: password)
        return try wallet.getKey(at: 0).sign(hash: data)
    }
}
