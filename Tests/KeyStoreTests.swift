// Copyright © 2017 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

@testable import TrustKeystore
import XCTest

class KeyStoreTests: XCTestCase {
    var keydir: URL!

    override func setUp() {
        super.setUp()

        let fileManager = FileManager.default

        keydir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("KeyStoreTests")
        try? fileManager.removeItem(at: keydir)
        try? fileManager.createDirectory(at: keydir, withIntermediateDirectories: true, attributes: nil)

        let walletURL = Bundle(for: type(of: self)).url(forResource: "wallet", withExtension: "json")!
        let destination = keydir.appendingPathComponent("wallet.json")

        try? fileManager.removeItem(at: destination)
        try? fileManager.copyItem(at: walletURL, to: destination)
    }

    func testLoadKeyStore() {
        let keyStore = try! KeyStore(keydir: keydir)
        let account = keyStore.account(for: Address(string: "008aeeda4d805471df9b2a5b0f38a0c3bcba786b"))
        XCTAssertNotNil(account)
    }

    @available(iOS 10.0, *)
    func testCreateAccount() {
        let keyStore = try! KeyStore(keydir: keydir)
        let newAccount = try! keyStore.createAccount(password: "password")

        XCTAssertNotNil(keyStore.account(for: newAccount.address))
        XCTAssertEqual(keyStore.accounts.count, 2)
    }

    func testUpdateAccount() {
        let keyStore = try! KeyStore(keydir: keydir)
        try! keyStore.update(account: keyStore.accounts.first!, password: "testpassword", newPassword: "password")

        let key = keyStore.key(for: Address(string: "008aeeda4d805471df9b2a5b0f38a0c3bcba786b"))
        XCTAssertNotNil(key)
        XCTAssertNoThrow(try key!.decrypt(password: "password"))
    }

    func testDeleteAccount() {
        let keyStore = try! KeyStore(keydir: keydir)
        try! keyStore.delete(account: keyStore.accounts.first!, password: "testpassword")
        XCTAssertTrue(keyStore.accounts.isEmpty)
    }
}