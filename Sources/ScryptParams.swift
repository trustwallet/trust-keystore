// Copyright © 2017 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import Foundation

/// Scrypt function parameters.
public struct ScryptParams {
    /// Random salt.
    public var salt: Data

    /// Desired key length in bytes.
    public var derivedKeyLength = 32

    /// CPU/Memory cost factor.
    public var n = 1 << 18

    /// Parallelization factor (1..232-1 * hLen/MFlen).
    public var p = 1

    /// Block size factor.
    public var r = 8

    /// Initializes with default scrypt parameters and a random salt.
    public init() {
        let length = 32
        var data = Data(repeating: 0, count: length)
        let result = data.withUnsafeMutableBytes { p in
            SecRandomCopyBytes(kSecRandomDefault, length, p)
        }
        precondition(result == errSecSuccess, "Failed to generate random number")
        salt = data
    }

    /// Initializes `ScryptParams` with all values.
    public init(salt: Data, n: Int, r: Int, p: Int, derivedKeyLength: Int) throws {
        self.salt = salt
        self.n = n
        self.r = r
        self.p = p
        self.derivedKeyLength = derivedKeyLength
        if let error = validate() {
            throw error
        }
    }

    /// Validates the parameters.
    ///
    /// - Returns: a `ValidationError` or `nil` if the parameters are valid.
    public func validate() -> ValidationError? {
        if derivedKeyLength > ((1 << 32) - 1) * 32 {
            return ValidationError.desiredKeyLengthTooLarge
        }
        if UInt64(r) * UInt64(p) >= (1 << 30) {
            return ValidationError.blockSizeTooLarge
        }
        if n & (n - 1) != 0 || n < 2 {
            return ValidationError.invalidCostFactor
        }
        if (r > Int.max / 128 / p) || (n > Int.max / 128 / r) {
            return ValidationError.overflow
        }
        return nil
    }

    public enum ValidationError: Error {
        case desiredKeyLengthTooLarge
        case blockSizeTooLarge
        case invalidCostFactor
        case overflow
    }
}

extension ScryptParams: Codable {
    enum CodingKeys: String, CodingKey {
        case salt
        case derivedKeyLength = "dklen"
        case n
        case p
        case r
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        salt = try values.decodeHexString(forKey: .salt)
        derivedKeyLength = try values.decode(Int.self, forKey: .derivedKeyLength)
        n = try values.decode(Int.self, forKey: .n)
        p = try values.decode(Int.self, forKey: .p)
        r = try values.decode(Int.self, forKey: .r)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(salt.hexString, forKey: .salt)
        try container.encode(derivedKeyLength, forKey: .derivedKeyLength)
        try container.encode(n, forKey: .n)
        try container.encode(p, forKey: .p)
        try container.encode(r, forKey: .r)
    }
}
