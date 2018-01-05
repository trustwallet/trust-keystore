// Copyright © 2017 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import Foundation

/// Ethereum account representation.
public struct Account {
    /// Ethereum 20-byte account address derived from the key.
    public var address: Data

    /// Optional URL for the key file on disk.
    public var url: URL?

    /// Account key.
    public var key: Key
}
