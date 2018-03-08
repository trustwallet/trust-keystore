// Copyright © 2017-2018 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import TrezorCrypto

/// A hierarchical deterministic wallet.
public class Wallet {
    public static let defaultPath = "m/44'/60'/0'/0/x"

    /// Wallet seed.
    public var seed: Data

    /// Mnemonic word list.
    public var mnemonic: String

    /// Mnemonic passphrase.
    public var passphrase: String

    /// Derivation path.
    public var path: String

    /// Initializes a wallet from a mnemonic string and a passphrase.
    public init(mnemonic: String, passphrase: String = "", path: String = Wallet.defaultPath) {
        seed = Mnemonic.deriveSeed(mnemonic: mnemonic, passphrase: passphrase)
        self.mnemonic = mnemonic
        self.passphrase = ""
        self.path = path
    }

    private func getDerivationPath(for index: Int) -> DerivationPath {
        guard let path = DerivationPath(path.replacingOccurrences(of: "x", with: String(index))) else {
            preconditionFailure("Invalid derivation path string")
        }
        return path
    }

    private func getNode(for derivationPath: DerivationPath) -> HDNode {
        var node = HDNode()
        hdnode_from_seed(seed.bytes, Int32(seed.count), "secp256k1", &node)
        for index in derivationPath.indices {
            hdnode_private_ckd(&node, index.derivationIndex)
        }
        return node
    }

    /// Generates the key at the specified derivation path index.
    public func getKey(at index: Int) -> HDKey {
        let node = getNode(for: getDerivationPath(for: index))
        return HDKey(node: node)
    }
}
