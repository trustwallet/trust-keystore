// Copyright © 2017 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import Foundation

public struct Address: Hashable, CustomStringConvertible {
    public private(set) var data: Data

    /// Creates an address with `Data`.
    ///
    /// - Precondition: data contains exactly 20 bytes
    public init(data: Data) {
        precondition(data.count == 20, "Address length should be 20 bytes")
        self.data = data
    }

    /// Creates an address with a hexadecimal string.
    public init(string: String) {
        guard let data = Data(hexString: string), data.count == 20 else {
            preconditionFailure("Address length should be 20 bytes")
        }
        self.data = data
    }

    public var description: String {
        return data.hexString
    }

    public var hashValue: Int {
        return data.hashValue
    }

    public static func == (lhs: Address, rhs: Address) -> Bool {
        return lhs.data == rhs.data
    }
}
