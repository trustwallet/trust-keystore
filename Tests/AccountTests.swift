// Copyright © 2017-2018 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import TrustCore
import TrustKeystore
import XCTest

class AccountTests: XCTestCase {

    let words = "ripple scissors kick mammal hire column oak again sun offer wealth tomorrow wagon turn fatal"
    let passphrase = "TREZOR"
    let password = "password"

    func testSignHash() throws {
        let privateKey = PrivateKey(data: Data(hexString: "D30519BCAE8D180DBFCC94FE0B8383DC310185B0BE97B4365083EBCECCD75759")!)!
        let key = try KeystoreKey(password: "password", key: privateKey, coin: .ethereum)
        let wallet = Wallet(keyURL: URL(fileURLWithPath: "/"), key: key)
        let account = try wallet.getAccount(password: "password", coin: .ethereum)

        let hash = Data(hexString: "3F891FDA3704F0368DAB65FA81EBE616F4AA2A0854995DA4DC0B59D2CADBD64F")!
        let result = try account.sign(hash: hash, password: "password")

        let publicKey = privateKey.publicKey()
        XCTAssertEqual(result.count, 65)
        XCTAssertTrue(Crypto.verify(signature: result, message: hash, publicKey: publicKey.data))
    }

    func testSignHashHD() throws {
        let key = try KeystoreKey(password: password, mnemonic: words, passphrase: passphrase)
        let wallet = Wallet(keyURL: URL(fileURLWithPath: "/"), key: key)
        let account = try wallet.getAccounts(derivationPaths: [Ethereum().derivationPath(at: 0)], password: "password").first!

        let hash = Data(hexString: "3F891FDA3704F0368DAB65FA81EBE616F4AA2A0854995DA4DC0B59D2CADBD64F")!
        let result = try account.sign(hash: hash, password: "password")

        let publicKey = try account.privateKey(password: "password").publicKey()
        XCTAssertEqual(result.count, 65)
        XCTAssertTrue(Crypto.verify(signature: result, message: hash, publicKey: publicKey.data))
    }

    func testExtendedPubkey() throws {
        let key = try KeystoreKey(password: password, mnemonic: words, passphrase: passphrase)
        let wallet = Wallet(keyURL: URL(fileURLWithPath: "/"), key: key)
        let account = try wallet.getAccounts(derivationPaths: [Bitcoin().derivationPath(at: 0)], password: "password").first!

        XCTAssertEqual(account.extendedPublicKey, "zpub6s2aob62srpiGYm3pjS5qNYDA3ipDAvFVifHgndVF8m7qRnKaLut7aKBrd88aeqPeVhRxZwjgfDjePkPZ5AMpz3fA6eiBkBgkuFgkkMNb3i")
    }

    func testPrivateKeyWithPaths() throws {
        let bitcoin = Bitcoin()
        let key = try KeystoreKey(password: password, mnemonic: words, passphrase: passphrase)
        let wallet = Wallet(keyURL: URL(fileURLWithPath: "/"), key: key)
        let account = try wallet.getAccounts(derivationPaths: [bitcoin.derivationPath(at: 0)], password: "password").first!

        let privateKey0 = try account.privateKey(at: bitcoin.derivationPath(at: 0), password: password)
        XCTAssertEqual(privateKey0, try account.privateKey(password: password))
        XCTAssertEqual(privateKey0, PrivateKey(wif: "Kx4KYjQdy67za4Eu8YPQiXdUAAuX6F613TeKexiSnmm7HFLFFAHs")!)

        let privateKey4 = try account.privateKey(at: bitcoin.derivationPath(at: 4), password: password)
        XCTAssertEqual(privateKey4, PrivateKey(wif: "L5TR7ugNy3MgwN9GjsFYgAi4mE1aZqr7JhH1EhfRZxAeLtgxppNi")!)

        let privateKeyChange2 = try account.privateKey(at: bitcoin.derivationPath(account: 0, change: 1, at: 2), password: password)
        XCTAssertEqual(privateKeyChange2, PrivateKey(wif: "Kya3aLWeRoKc8mK3LmsuwmysVi5kW1SddnAN5PnP5caLbEergikB")!)
    }
}
