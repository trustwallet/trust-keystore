// Copyright © 2017 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import Foundation
import secp256k1

public final class Secp256k1 {
    public static let shared = Secp256k1()
    private let context: OpaquePointer

    public init() {
        context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN))!
    }

    deinit {
        secp256k1_context_destroy(context)
    }

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
}
