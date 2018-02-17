// Copyright © 2017-2018 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

@testable import TrustKeystore
import XCTest

class WalletStoreTests: XCTestCase {
    var directory: URL!

    override func setUp() {
        super.setUp()

        let fileManager = FileManager.default

        directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("WalletStoreTests")
        try? fileManager.removeItem(at: directory)
        try? fileManager.createDirectory(at: directory, withIntermediateDirectories: true, attributes: nil)

        let walletURL = Bundle(for: type(of: self)).url(forResource: "wallet", withExtension: "json")!
        let destination = directory.appendingPathComponent("wallet.json")

        try? fileManager.removeItem(at: destination)
        try? fileManager.copyItem(at: walletURL, to: destination)
    }

    func testLoadWalletStore() {
        let walletStore = try! WalletStore(directory: directory)
        let account = walletStore.wallet(for: Address(string: "0x27Ef5cDBe01777D62438AfFeb695e33fC2335979")!)
        XCTAssertNotNil(account)
    }

    @available(iOS 10.0, *)
    func testCreateWallet() {
        let walletStore = try! WalletStore(directory: directory)
        let newWallet = try! walletStore.createWallet(password: "password")

        XCTAssertNotNil(walletStore.wallet(for: newWallet.address))
        XCTAssertEqual(walletStore.wallets.count, 2)
    }

    func testDeleteWallet() {
        let walletStore = try! WalletStore(directory: directory)
        try! walletStore.delete(wallet: walletStore.wallets.first!, password: "TREZOR")
        XCTAssertTrue(walletStore.wallets.isEmpty)
    }

    func testImport() {
        let walletStore = try! WalletStore(directory: directory)
        let privateKey = Data(hexString: "9cdb5cab19aec3bd0fcd614c5f185e7a1d97634d4225730eba22497dc89a716c")!
        let key = try! KeystoreKey(password: "password", key: privateKey)
        let json = try! JSONEncoder().encode(key)

        let wallet = try! walletStore.import(mnemonic: "ripple scissors kick mammal hire column oak again sun offer wealth tomorrow wagon turn back", password: "password")

        XCTAssertNotNil(walletStore.wallet(for: wallet.address))
        XCTAssertNoThrow(try walletStore.signHash(Data(repeating: 0, count: 32), wallet: wallet, password: "password"))
    }
}
