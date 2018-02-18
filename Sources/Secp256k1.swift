// Copyright © 2017-2018 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import Foundation
import secp256k1_ios

/// `Secp256k1` provides functions for the ECDSA curve used in Ethereum.
///
/// - SeeAlso: Standards for Efficient Cryptography (SEC) (Certicom Research, http://www.secg.org/sec2-v2.pdf)
public final class Secp256k1 {
    public static let shared = Secp256k1()
    private let context: OpaquePointer

    public init() {
        context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY))!
    }

    deinit {
        secp256k1_context_destroy(context)
    }

    /// Extracts the public key from a private key.
    public func pubicKey(from privateKey: Data) -> Data {
        var pubKey = secp256k1_pubkey()
        var pubKeyData = Data(count: 65)
        _ = privateKey.withUnsafeBytes { key in
            secp256k1_ec_pubkey_create(context, &pubKey, key)
        }
        _ = pubKeyData.withUnsafeMutableBytes { (output: UnsafeMutablePointer<UInt8>) in
            var len = pubKeyData.count
            secp256k1_ec_pubkey_serialize(context, output, &len, &pubKey, UInt32(SECP256K1_EC_UNCOMPRESSED))
        }
        return pubKeyData
    }

    /// Signs a hash with a private key.
    ///
    /// - Parameters:
    ///   - hash: hash to sign
    ///   - privateKey: private key to use for signing
    /// - Returns: signature is in the 65-byte [R || S || V] format where V is 0 or 1.
    /// - Throws: `Secp256k1Error` if the private key is invalid.
    public func sign(hash: Data, privateKey: Data) throws -> Data {
        precondition(hash.count == 32, "Expect hash size to be 32")
        precondition(privateKey.count == 32, "Expect private key size to be 32")

        var signature = secp256k1_ecdsa_recoverable_signature()
        try privateKey.withUnsafeBytes { (key: UnsafePointer<UInt8>) in
            if secp256k1_ec_seckey_verify(context, key) != 1 {
                throw Secp256k1Error.invalidPrivateKey
            }
            let result = hash.withUnsafeBytes { hash in
                secp256k1_ecdsa_sign_recoverable(context, &signature, hash, key, nil, nil)
            }
            if result == 0 {
                throw Secp256k1Error.invalidPrivateKey
            }
        }

        var output = Data(count: 65)
        var recid = 0 as Int32
        _ = output.withUnsafeMutableBytes { (output: UnsafeMutablePointer<UInt8>) in
            secp256k1_ecdsa_recoverable_signature_serialize_compact(context, output, &recid, &signature)
        }

        // add back recid to get 65 bytes sig
        output[64] = UInt8(recid)

        return output
    }

    /// Verifies a hash signature.
    ///
    /// - Parameters:
    ///   - signature: signature to verify
    ///   - message: message to verify
    ///   - publicKey: public key to verify with
    /// - Returns: whether the signature is valid
    /// - Throws: `Secp256k1Error` if the signature or the public key are invalid.
    public func verify(signature: Data, message: Data, publicKey: Data) throws -> Bool {
        var sig = secp256k1_ecdsa_signature()
        let sigParseResult = signature.withUnsafeBytes { signature in
            secp256k1_ecdsa_signature_parse_compact(context, &sig, signature)
        }
        if sigParseResult == 0 {
            throw Secp256k1Error.invalidSignature
        }

        var pubkey = secp256k1_pubkey()
        let keyParseResult = publicKey.withUnsafeBytes { pointer in
            secp256k1_ec_pubkey_parse(context, &pubkey, pointer, publicKey.count)
        }
        if keyParseResult == 0 {
            throw Secp256k1Error.invalidPublicKey
        }

        let result = message.withUnsafeBytes { message in
            secp256k1_ecdsa_verify(context, &sig, message, &pubkey)
        }
        return result == 1
    }
}

public enum Secp256k1Error: Error {
    case invalidPrivateKey
    case invalidPublicKey
    case invalidSignature
}
