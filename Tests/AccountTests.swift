// Copyright © 2017-2018 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import TrustCore
import TrustKeystore
import XCTest

class AccountTests: XCTestCase {
    func testSignHash() throws {
        let privateKey = PrivateKey(data: Data(hexString: "D30519BCAE8D180DBFCC94FE0B8383DC310185B0BE97B4365083EBCECCD75759")!)!
        let key = try KeystoreKey(password: "password", key: privateKey, coin: .ethereum)
        let wallet = Wallet(keyURL: URL(fileURLWithPath: "/"), key: key)
        let account = try wallet.getAccount(password: "password")

        let hash = Data(hexString: "3F891FDA3704F0368DAB65FA81EBE616F4AA2A0854995DA4DC0B59D2CADBD64F")!
        let result = try account.sign(hash: hash, password: "password")

        let publicKey = privateKey.publicKey(for: .ethereum)
        XCTAssertEqual(result.count, 65)
        XCTAssertTrue(Crypto.verify(signature: result, message: hash, publicKey: publicKey.data))
    }

    func testSignHashHD() throws {
        let words = "ripple scissors kick mammal hire column oak again sun offer wealth tomorrow wagon turn fatal"
        let passphrase = "TREZOR"

        let key = try KeystoreKey(password: "password", mnemonic: words, passphrase: passphrase)
        let wallet = Wallet(keyURL: URL(fileURLWithPath: "/"), key: key)
        let account = try wallet.getAccounts(derivationPaths: [Coin.ethereum.derivationPath(at: 0)], password: "password").first!

        let hash = Data(hexString: "3F891FDA3704F0368DAB65FA81EBE616F4AA2A0854995DA4DC0B59D2CADBD64F")!
        let result = try account.sign(hash: hash, password: "password")

        let publicKey = try account.privateKey(password: "password").publicKey(for: .ethereum)
        XCTAssertEqual(result.count, 65)
        XCTAssertTrue(Crypto.verify(signature: result, message: hash, publicKey: publicKey.data))
    }
}
