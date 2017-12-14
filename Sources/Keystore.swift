// Copyright © 2017 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import Foundation

/// Key derivation function parameters
public struct KDFParams: Codable {
    /// Random salt.
    public var salt: String

    /// Desired key length in bytes.
    public var dklen: Int

    /// CPU/Memory cost factor.
    public var n: Int?

    /// Parallelization factor (1..232-1 * hLen/MFlen).
    public var p: Int?

    /// Block size factor.
    public var r: Int?
}

public struct CipherParams: Codable {
    public var iv: String
}

/// Encrypted private key and crypto parameters.
public struct Crypto: Codable {
    /// Encrypted data.
    public var cipherText: String

    /// Cipher algorithm.
    public var cipher: String

    /// Cipher parameters.
    public var cipherParams: CipherParams

    /// Key derivation function, must be scrypt.
    public var kdf: String

    /// Key derivation function parameters.
    public var kdfparams: KDFParams

    /// Message authentication code.
    public var mac: String
}

/// Keystore wallet definition.
public struct Keystore: Codable {
    /// Ethereum address, optional.
    public var address: String?

    /// Wallet UUID, optional.
    public var id: String?

    /// Encryped private key and crypto parameters.
    public var crypto: Crypto

    /// Keystore version, must be 3.
    public var version: Int
}
