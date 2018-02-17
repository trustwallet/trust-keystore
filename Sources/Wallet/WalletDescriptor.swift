// Copyright © 2017-2018 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import Foundation

public struct WalletDescriptor {
    /// Wallet's mnemominc phrase.
    public var mnemonic: String

    /// Ethereum address at index 0.
    public var address: Address

    /// Wallet UUID.
    public var id = UUID()

    /// URL for the wallet file on disk.
    public var url: URL

    /// Creates a new `WalletDescriptor`.
    public init(mnemonic: String, address: Address, url: URL) {
        self.mnemonic = mnemonic
        self.address = address
        self.url = url
    }

    /// Initializes a `WalletDescriptor` from a JSON wallet.
    public init(contentsOf url: URL) throws {
        let data = try Data(contentsOf: url)
        self = try JSONDecoder().decode(WalletDescriptor.self, from: data)
        self.url = url
    }

    /// Generates a unique file name for an address.
    public static func generateFileName(address: Address, date: Date = Date(), timeZone: TimeZone = .current) -> String {
        // keyFileName implements the naming convention for keyfiles:
        // UTC--<created_at UTC ISO8601>-<address hex>
        return "UTC--\(filenameTimestamp(for: date, in: timeZone))--\(address.data.hexString)"
    }

    private static func filenameTimestamp(for date: Date, in timeZone: TimeZone = .current) -> String {
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
}

extension WalletDescriptor: Codable {
    enum CodingKeys: String, CodingKey {
        case mnemonic
        case address
        case id
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        mnemonic = try values.decode(String.self, forKey: .mnemonic)
        address = Address(data: try values.decodeHexString(forKey: .address))
        id = UUID(uuidString: try values.decode(String.self, forKey: .id)) ?? UUID()
        url = URL(string: "/")!
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(mnemonic, forKey: .mnemonic)
        try container.encode(address.description, forKey: .address)
        try container.encode(id.uuidString, forKey: .id)
    }
}
