// Copyright © 2017 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import Foundation

/// Scrypt function parameters.
public struct ScryptParams: Codable {
    /// Random salt.
    public var salt: String

    /// Desired key length in bytes.
    public var dklen = 32

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
        salt = data.hexString
    }

    /// Initializes `ScryptParams` with all values.
    public init(salt: String, n: Int, r: Int, p: Int, dklen: Int) throws {
        self.salt = salt
        self.n = n
        self.r = r
        self.p = p
        self.dklen = dklen
        if let error = validate() {
            throw error
        }
    }

    /// Validates the parameters.
    ///
    /// - Returns: a `ValidationError` or `nil` if the parameters are valid.
    public func validate() -> ValidationError? {
        if dklen > ((1 << 32) - 1) * 32 {
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
