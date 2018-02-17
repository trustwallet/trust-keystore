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

        let walletURL = Bundle(for: type(of: self)).url(forResource: "key", withExtension: "json")!
        let destination = keydir.appendingPathComponent("key.json")

        try? fileManager.removeItem(at: destination)
        try? fileManager.copyItem(at: walletURL, to: destination)
    }

    func testLoadKeyStore() {
        let keyStore = try! KeyStore(keydir: keydir)
        let account = keyStore.account(for: Address(string: "008aeeda4d805471df9b2a5b0f38a0c3bcba786b")!)
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
        let account = keyStore.accounts.first!
        try! keyStore.update(account: account, password: "testpassword", newPassword: "password")
        XCTAssertNoThrow(try keyStore.signHash(Data(repeating: 0, count: 32), account: account, password: "password"))
    }

    func testDeleteAccount() {
        let keyStore = try! KeyStore(keydir: keydir)
        try! keyStore.delete(account: keyStore.accounts.first!, password: "testpassword")
        XCTAssertTrue(keyStore.accounts.isEmpty)
    }

    func testImport() {
        let keyStore = try! KeyStore(keydir: keydir)
        let privateKey = Data(hexString: "9cdb5cab19aec3bd0fcd614c5f185e7a1d97634d4225730eba22497dc89a716c")!
        let key = try! KeystoreKey(password: "password", key: privateKey)
        let json = try! JSONEncoder().encode(key)

        let account = try! keyStore.import(json: json, password: "password", newPassword: "newPassword")

        XCTAssertNotNil(keyStore.account(for: account.address))
        XCTAssertNoThrow(try keyStore.signHash(Data(repeating: 0, count: 32), account: account, password: "newPassword"))
    }
}
