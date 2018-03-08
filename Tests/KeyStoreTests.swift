// Copyright © 2017-2018 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

@testable import TrustKeystore
import XCTest

class KeyStoreTests: XCTestCase {
    let keyAddress = Address(eip55: "0x008AeEda4D805471dF9b2A5B0f38A0C3bCBA786b")!
    let walletAddress = Address(eip55: "0x32dd55E0BCF509a35A3F5eEb8593fbEb244796b1")!

    var keyDirectory: URL!

    override func setUp() {
        super.setUp()

        let fileManager = FileManager.default

        keyDirectory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("KeyStoreTests")
        try? fileManager.removeItem(at: keyDirectory)
        try? fileManager.createDirectory(at: keyDirectory, withIntermediateDirectories: true, attributes: nil)

        let keyURL = Bundle(for: type(of: self)).url(forResource: "key", withExtension: "json")!
        let keyDestination = keyDirectory.appendingPathComponent("key.json")

        try? fileManager.removeItem(at: keyDestination)
        try? fileManager.copyItem(at: keyURL, to: keyDestination)

        let walletURL = Bundle(for: type(of: self)).url(forResource: "wallet", withExtension: "json")!
        let walletDestination = keyDirectory.appendingPathComponent("wallet.json")

        try? fileManager.removeItem(at: walletDestination)
        try? fileManager.copyItem(at: walletURL, to: walletDestination)
    }

    func testLoadKeyStore() {
        let keyStore = try! KeyStore(keyDirectory: keyDirectory)

        let keyAccount = keyStore.account(for: keyAddress)
        XCTAssertNotNil(keyAccount)

        let walletAccount = keyStore.account(for: walletAddress)
        XCTAssertNotNil(walletAccount)
    }

    func testCreateKey() {
        let keyStore = try! KeyStore(keyDirectory: keyDirectory)
        let newAccount = try! keyStore.createAccount(password: "password", type: .encryptedKey)

        XCTAssertNotNil(keyStore.account(for: newAccount.address))
        XCTAssertEqual(keyStore.accounts.count, 3)
    }

    func testCreateWallet() {
        let keyStore = try! KeyStore(keyDirectory: keyDirectory)
        let newAccount = try! keyStore.createAccount(password: "password", type: .hierarchicalDeterministicWallet)

        XCTAssertNotNil(keyStore.account(for: newAccount.address))
        XCTAssertEqual(keyStore.accounts.count, 3)
    }

    func testUpdateKey() {
        let keyStore = try! KeyStore(keyDirectory: keyDirectory)
        let account = keyStore.account(for: keyAddress)!
        try! keyStore.update(account: account, password: "testpassword", newPassword: "password")
        XCTAssertNoThrow(try keyStore.signHash(Data(repeating: 0, count: 32), account: account, password: "password"))
    }

    func testSigningMultiple() {
        let keyStore = try! KeyStore(keyDirectory: keyDirectory)
        let account = keyStore.account(for: keyAddress)!
        var multipleMessages = [Data]()
        for _ in 0...2000 {
            multipleMessages.append(Data(repeating: 0, count: 32))
        }
        XCTAssertNoThrow(try keyStore.signHashes(multipleMessages, account: account, password: "testpassword"))
    }

    func testDeleteKey() {
        let keyStore = try! KeyStore(keyDirectory: keyDirectory)
        try! keyStore.delete(account: keyStore.account(for: keyAddress)!, password: "testpassword")
        XCTAssertNil(keyStore.account(for: keyAddress))
    }

    func testDeleteWallet() {
        let keyStore = try! KeyStore(keyDirectory: keyDirectory)
        try! keyStore.delete(account: keyStore.account(for: walletAddress)!, password: "password")
        XCTAssertNil(keyStore.account(for: walletAddress))
    }

    func testImportKey() {
        let keyStore = try! KeyStore(keyDirectory: keyDirectory)
        let privateKey = Data(hexString: "9cdb5cab19aec3bd0fcd614c5f185e7a1d97634d4225730eba22497dc89a716c")!
        let key = try! KeystoreKey(password: "password", key: privateKey)
        let json = try! JSONEncoder().encode(key)

        let account = try! keyStore.import(json: json, password: "password", newPassword: "newPassword")

        XCTAssertNotNil(keyStore.account(for: account.address))
        XCTAssertNoThrow(try keyStore.signHash(Data(repeating: 0, count: 32), account: account, password: "newPassword"))
    }

    func testImportWallet() throws {
        let keyStore = try KeyStore(keyDirectory: keyDirectory)
        let account = try keyStore.import(mnemonic: "ripple scissors kick mammal hire column oak again sun offer wealth tomorrow wagon turn back", passphrase: "TREZOR", encryptPassword: "newPassword")

        XCTAssertNotNil(keyStore.account(for: account.address))
        XCTAssertNoThrow(try keyStore.signHash(Data(repeating: 0, count: 32), account: account, password: "newPassword"))
    }

    func testFileName() {
        let keyStore = try! KeyStore(keyDirectory: keyDirectory)

        let timeZone = TimeZone(secondsFromGMT: -480)!
        let date = DateComponents(calendar: Calendar(identifier: .iso8601), timeZone: timeZone, year: 2018, month: 1, day: 2, hour: 20, minute: 55, second: 25, nanosecond: 186770975).date!
        let fileName = keyStore.generateFileName(address: keyAddress, date: date, timeZone: timeZone)

        XCTAssertEqual(fileName, "UTC--2018-01-02T20-55-25.186770975-0800--008aeeda4d805471df9b2a5b0f38a0c3bcba786b")
    }

    func testFileNameUTC() {
        let keyStore = try! KeyStore(keyDirectory: keyDirectory)

        let timeZone = TimeZone(abbreviation: "UTC")!
        let date = DateComponents(calendar: Calendar(identifier: .iso8601), timeZone: timeZone, year: 2018, month: 1, day: 2, hour: 20, minute: 55, second: 25, nanosecond: 186770975).date!
        let fileName = keyStore.generateFileName(address: keyAddress, date: date, timeZone: timeZone)

        XCTAssertEqual(fileName, "UTC--2018-01-02T20-55-25.186770975Z--008aeeda4d805471df9b2a5b0f38a0c3bcba786b")
    }
}
