// Copyright © 2017 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import Foundation

public final class KeyStore {
    public let keydir: URL
    private var accountsByAddress = [Data: Account]()
    
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
                let account = Account(address: key.address, url: url, key: key)
                accountsByAddress[key.address] = account
            } catch {
                // Ignore invalid keys
            }
        }
    }

    /// Creates a new account.
    @available(iOS 10.0, *)
    public func createAccount(password: String) throws -> Account {
        let key = try Key(password: password)
        let fileName = key.generateFileName()
        let url = keydir.appendingPathComponent(fileName)
        let account = Account(address: key.address, url: url, key: key)
        accountsByAddress[key.address] = account
        return account
    }
}
