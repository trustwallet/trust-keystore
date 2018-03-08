// Copyright © 2017-2018 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import Foundation
import TrezorCrypto

public final class Mnemonic {
    /// Generates a menmoic string with the given strength in bits.
    ///
    /// - Precondition: `strength` is a multiple of 32 between 128 and 256
    /// - Parameter strength: strength in bits
    /// - Returns: mnemonic string
    public static func generate(strength: Int) -> String {
        precondition(strength % 32 == 0 && strength >= 128 && strength <= 256)
        let rawString = mnemonic_generate(Int32(strength))!
        return String(cString: rawString)
    }

    /// Generates a mnemonic from seed data.
    ///
    /// - Precondition: the length of `data` is a multiple of 4 between 16 and 32
    /// - Parameter data: seed data for the mnemonic
    /// - Returns: mnemonic string
    public static func generate(from data: Data) -> String {
        precondition(data.count % 4 == 0 && data.count >= 16 && data.count <= 32)
        let rawString = data.withUnsafeBytes { dataPtr in
            mnemonic_from_data(dataPtr, Int32(data.count))!
        }
        return String(cString: rawString)
    }

    /// Determines if a mnemonic string is valid.
    ///
    /// - Parameter string: mnemonic string
    /// - Returns: `true` if the string is valid; `false` otherwise.
    public static func isValid(_ string: String) -> Bool {
        return mnemonic_check(string) != 0
    }

    /// Derives the wallet seed.
    ///
    /// - Parameters:
    ///   - mnemonic: mnemonic string
    ///   - passphrase: mnemonic passphrase
    /// - Returns: wallet seed
    public static func deriveSeed(mnemonic: String, passphrase: String) -> Data {
        precondition(passphrase.count <= 256, "Passphrase too long")
        var seed = Data(repeating: 0, count: 512 / 8)
        seed.withUnsafeMutableBytes { seedPtr in
            mnemonic_to_seed(mnemonic, passphrase, seedPtr, nil)
        }
        return seed
    }
}

extension Mnemonic {
    enum Error: Swift.Error {
        case invalidStrength
    }
}
