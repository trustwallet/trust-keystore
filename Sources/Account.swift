// Copyright © 2017-2018 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import Foundation
import TrustCore

/// Ethereum account representation.
public struct Account: Hashable {
    /// Ethereum 20-byte account address derived from the key.
    public var address: Address

    /// Account type.
    public var type: AccountType

    /// URL for the key file on disk.
    public var url: URL

    /// Creates an `Account` with an Ethereum address and a `Key`.
    public init(address: Address, type: AccountType, url: URL) {
        self.address = address
        self.type = type
        self.url = url
    }

    public var hashValue: Int {
        return address.hashValue
    }

    public static func == (lhs: Account, rhs: Account) -> Bool {
        return lhs.address == rhs.address
    }
}

/// Support account types.
public enum AccountType {
    case encryptedKey
    case hierarchicalDeterministicWallet
}
