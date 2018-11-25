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
        let key = try KeystoreKey(password: password, key: privateKey, coin: .ethereum)
        let wallet = Wallet(keyURL: URL(fileURLWithPath: "/"), key: key)
        let account = try wallet.getAccount(password: password, coin: .ethereum)

        let hash = Data(hexString: "3F891FDA3704F0368DAB65FA81EBE616F4AA2A0854995DA4DC0B59D2CADBD64F")!
        let result = try account.sign(hash: hash, password: password)

        let publicKey = privateKey.publicKey()
        XCTAssertEqual(result.count, 65)
        XCTAssertTrue(Crypto.verify(signature: result, message: hash, publicKey: publicKey.data))
    }

    func testSignHashHD() throws {
        let key = try KeystoreKey(password: password, mnemonic: words, passphrase: passphrase)
        let wallet = Wallet(keyURL: URL(fileURLWithPath: "/"), key: key)
        let account = try wallet.getAccounts(derivationPaths: [Ethereum().derivationPath(at: 0)], password: password).first!

        let hash = Data(hexString: "3F891FDA3704F0368DAB65FA81EBE616F4AA2A0854995DA4DC0B59D2CADBD64F")!
        let result = try account.sign(hash: hash, password: password)

        let publicKey = try account.privateKey(password: password).publicKey()
        XCTAssertEqual(result.count, 65)
        XCTAssertTrue(Crypto.verify(signature: result, message: hash, publicKey: publicKey.data))
    }

    func testExtendedPubkey() throws {
        let key = try KeystoreKey(password: password, mnemonic: words, passphrase: passphrase)
        let wallet = Wallet(keyURL: URL(fileURLWithPath: "/"), key: key)
        let accounts = try wallet.getAccounts(derivationPaths: [
            Bitcoin().derivationPath(at: 0),
            BitcoinCash().derivationPath(at: 0),
            ], password: password)

        XCTAssertEqual(accounts[0].extendedPublicKey, "zpub6s2aob62srpiGYm3pjS5qNYDA3ipDAvFVifHgndVF8m7qRnKaLut7aKBrd88aeqPeVhRxZwjgfDjePkPZ5AMpz3fA6eiBkBgkuFgkkMNb3i")
        XCTAssertEqual(accounts[1].extendedPublicKey, "xpub6CEHLxCHR9sNtpcxtaTPLNxvnY9SQtbcFdov22riJ7jmhxmLFvXAoLbjHSzwXwNNuxC1jUP6tsHzFV9rhW9YKELfmR9pJaKFaM8C3zMPgjw")
    }

    func testBTCPrivateKeyWithPaths() throws {
        let blockchain = Bitcoin()
        let key = try KeystoreKey(password: password, mnemonic: words, passphrase: passphrase)
        let wallet = Wallet(keyURL: URL(fileURLWithPath: "/"), key: key)
        let account = try wallet.getAccounts(derivationPaths: [blockchain.derivationPath(at: 0)], password: password).first!

        let paths = [blockchain.derivationPath(at: 0), blockchain.derivationPath(at: 4), blockchain.derivationPath(account: 0, change: 1, at: 2)]
        let privateKeys = try account.privateKeys(at: paths, password: password)
        XCTAssertEqual(privateKeys[0], try account.privateKey(password: password))
        XCTAssertEqual(privateKeys[0], PrivateKey(wif: "Kx4KYjQdy67za4Eu8YPQiXdUAAuX6F613TeKexiSnmm7HFLFFAHs")!)
        XCTAssertEqual(privateKeys[1], PrivateKey(wif: "L5TR7ugNy3MgwN9GjsFYgAi4mE1aZqr7JhH1EhfRZxAeLtgxppNi")!)
        XCTAssertEqual(privateKeys[2], PrivateKey(wif: "Kya3aLWeRoKc8mK3LmsuwmysVi5kW1SddnAN5PnP5caLbEergikB")!)
    }

    func testBCHPrivateKeyWithPaths() throws {
        let blockchain = BitcoinCash(purpose: .bip44)
        let key = try KeystoreKey(password: password, mnemonic: words, passphrase: passphrase)
        let wallet = Wallet(keyURL: URL(fileURLWithPath: "/"), key: key)
        let account = try wallet.getAccounts(derivationPaths: [blockchain.derivationPath(at: 0)], password: password).first!

        let paths = [blockchain.derivationPath(at: 0), blockchain.derivationPath(at: 4), blockchain.derivationPath(account: 0, change: 1, at: 2)]
        let privateKeys = try account.privateKeys(at: paths, password: password)
        XCTAssertEqual(privateKeys[0], try account.privateKey(password: password))
        XCTAssertEqual(privateKeys[0], PrivateKey(wif: "L2MprqcQNgmgZyeHb8jUb7LnPr13U5htchLavaL4W8VZN43ajhkc")!)
        XCTAssertEqual(privateKeys[1], PrivateKey(wif: "L4bptjCKEpjcjSFrhDefATUNTojYuNC6wztAARE93VRZrkbm3cFa")!)
        XCTAssertEqual(privateKeys[2], PrivateKey(wif: "KzhtjQiUzcQhAKjAEDbXHa6Skg7cyUr1ZnfpcZZTzY1yL49GSDBB")!)
    }
}
