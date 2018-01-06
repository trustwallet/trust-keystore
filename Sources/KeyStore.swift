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

    /// Creates a `KeyStore` for the given directory.
    public init(keydir: URL) throws {
        self.keydir = keydir
        try load()
    }

    private func load() throws {
        let fileManager = FileManager.default
        let accountURLs = try fileManager.contentsOfDirectory(at: keydir, includingPropertiesForKeys: [], options: [.skipsHiddenFiles])
        for url in accountURLs {
            do {
                let key = try Key(contentsOf: url)
                let account = Account(key: key, url: url)
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

    /// Creates a new account.
    @available(iOS 10.0, *)
    public func createAccount(password: String) throws -> Account {
        let key = try Key(password: password)
        let account = Account(key: key)
        try account.save(in: keydir)
        accountsByAddress[key.address] = account
        return account
    }

    /// Retrieves an account for the given address, if it exists.
    public func account(for address: Address) -> Account? {
        return accountsByAddress[address]
    }
}
