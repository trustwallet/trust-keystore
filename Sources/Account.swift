// Copyright © 2017 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import Foundation

/// Ethereum account representation.
public struct Account {
    /// Account key.
    public var key: Key

    /// Ethereum 20-byte account address derived from the key.
    public var address: Address {
        return key.address
    }

    /// Optional URL for the key file on disk.
    public var url: URL?

    /// Creates an `Account` with an Ethereum address and a `Key`.
    public init(key: Key, url: URL? = nil) {
        self.key = key
        self.url = url
    }

    /// Saves the account to the given directory.
    public func save(in directory: URL) throws {
        if let url = url {
            try save(to: url)
        } else {
            let url = directory.appendingPathComponent(key.generateFileName())
            try save(to: url)
        }
    }

    private func save(to url: URL) throws {
        let json = try JSONEncoder().encode(key)
        try json.write(to: url, options: [.atomicWrite])
    }
}
