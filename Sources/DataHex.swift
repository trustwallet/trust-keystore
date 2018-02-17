// Copyright © 2017-2018 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import Foundation

extension Data {
    /// Initializes `Data` with a hex string representation.
    public init?(hexString: String) {
        let string: Substring
        if hexString.hasPrefix("0x") {
            string = hexString.dropFirst(2)
        } else {
            string = Substring(hexString)
        }

        self.init(capacity: string.count / 2)
        for offset in stride(from: 0, to: string.count, by: 2) {
            let start = string.index(string.startIndex, offsetBy: offset)
            guard string.distance(from: start, to: string.endIndex) >= 2 else {
                let byte = string[start...]
                guard let number = UInt8(byte, radix: 16) else {
                    return nil
                }
                append(number)
                break
            }

            let end = string.index(string.startIndex, offsetBy: offset + 2)
            let byte = string[start ..< end]
            guard let number = UInt8(byte, radix: 16) else {
                return nil
            }
            append(number)
        }
    }

    /// Returns the hex string representation of the data.
    public var hexString: String {
        var string = ""
        for byte in self {
            string.append(String(format: "%02x", byte))
        }
        return string
    }
}

extension KeyedDecodingContainerProtocol {
    func decodeHexString(forKey key: Self.Key) throws -> Data {
        let hexString = try decode(String.self, forKey: key)
        guard let data = Data(hexString: hexString) else {
            throw DecodingError.dataCorruptedError(forKey: key, in: self, debugDescription: "Expected hexadecimal string")
        }
        return data
    }

    func decodeHexStringIfPresent(forKey key: Self.Key) throws -> Data? {
        guard let hexString = try decodeIfPresent(String.self, forKey: key) else {
            return nil
        }
        guard let data = Data(hexString: hexString) else {
            throw DecodingError.dataCorruptedError(forKey: key, in: self, debugDescription: "Expected hexadecimal string")
        }
        return data
    }
}
