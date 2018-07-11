// Copyright © 2017-2018 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import TrustCore
@testable import TrustKeystore
import XCTest

extension KeyStore {
    var keyWallet: Wallet? {
        return wallets.first(where: { $0.type == .encryptedKey })
    }

    var hdWallet: Wallet? {
        return wallets.first(where: { $0.type == .hierarchicalDeterministicWallet })
    }
}

class KeyStoreTests: XCTestCase {
    let keyAddress = EthereumAddress(string: "0x008AeEda4D805471dF9b2A5B0f38A0C3bCBA786b")!
    let walletAddress = EthereumAddress(string: "0x32dd55E0BCF509a35A3F5eEb8593fbEb244796b1")!

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
        XCTAssertEqual(keyStore.wallets.count, 2)
    }

    func testCreateWallet() throws {
        let keyStore = try KeyStore(keyDirectory: keyDirectory)
        let newWallet = try keyStore.createWallet(password: "password", type: .encryptedKey)

        XCTAssertEqual(keyStore.wallets.count, 3)
        XCTAssertNoThrow(try newWallet.getAccount(password: "password"))
    }

    func testCreateHDWallet() throws {
        let keyStore = try KeyStore(keyDirectory: keyDirectory)
        let newWallet = try keyStore.createWallet(password: "password", type: .hierarchicalDeterministicWallet)

        XCTAssertEqual(keyStore.wallets.count, 3)
        XCTAssertNoThrow(try newWallet.getAccount(blockchain: .ethereum, derivationPath: Blockchain.ethereum.defaultDerivationPath, password: "password"))
    }

    func testUpdateKey() throws {
        let keyStore = try KeyStore(keyDirectory: keyDirectory)
        let wallet = keyStore.keyWallet!
        try keyStore.update(wallet: wallet, password: "testpassword", newPassword: "password")
        let account = try wallet.getAccount(password: "password")

        XCTAssertNoThrow(try account.sign(hash: Data(repeating: 0, count: 32), password: "password"))
    }

    func testSigningMultiple() throws {
        let keyStore = try KeyStore(keyDirectory: keyDirectory)
        let wallet = keyStore.keyWallet!
        let account = try wallet.getAccount(password: "testpassword")

        var multipleMessages = [Data]()
        for _ in 0...2000 {
            multipleMessages.append(Data(repeating: 0, count: 32))
        }
        XCTAssertNoThrow(try account.signHashes(multipleMessages, password: "testpassword"))
    }

    func testDeleteKey() throws {
        let keyStore = try KeyStore(keyDirectory: keyDirectory)
        let wallet = keyStore.keyWallet!
        try keyStore.delete(wallet: wallet, password: "testpassword")
        XCTAssertNil(keyStore.keyWallet)
    }

    func testDeleteWallet() throws {
        let keyStore = try KeyStore(keyDirectory: keyDirectory)
        let wallet = keyStore.hdWallet!
        try keyStore.delete(wallet: wallet, password: "password")
        XCTAssertNil(keyStore.hdWallet)
    }

    func testImportKey() throws {
        let keyStore = try KeyStore(keyDirectory: keyDirectory)
        let privateKey = PrivateKey(data: Data(hexString: "9cdb5cab19aec3bd0fcd614c5f185e7a1d97634d4225730eba22497dc89a716c")!)!
        let key = try KeystoreKey(password: "password", key: privateKey)
        let json = try JSONEncoder().encode(key)

        let wallet = try keyStore.import(json: json, password: "password", newPassword: "newPassword")
        let account = try wallet.getAccount(password: "newPassword")

        XCTAssertNotNil(keyStore.keyWallet)
        XCTAssertNoThrow(try account.sign(hash: Data(repeating: 0, count: 32), password: "newPassword"))
    }

    func testImportWallet() throws {
        let keyStore = try KeyStore(keyDirectory: keyDirectory)
        let wallet = try keyStore.import(mnemonic: "often tobacco bread scare imitate song kind common bar forest yard wisdom", passphrase: "TREZOR", encryptPassword: "newPassword")
        let account = try wallet.getAccount(blockchain: .ethereum, derivationPath: Blockchain.ethereum.defaultDerivationPath, password: "newPassword")

        XCTAssertNotNil(keyStore.hdWallet)
        XCTAssertNoThrow(try account.sign(hash: Data(repeating: 0, count: 32), password: "newPassword"))
    }

    func testExportMnemonic() throws {
        let mnemonic = "often tobacco bread scare imitate song kind common bar forest yard wisdom"
        let keyStore = try KeyStore(keyDirectory: keyDirectory)
        let wallet = try keyStore.import(mnemonic: mnemonic, passphrase: "TREZOR", encryptPassword: "newPassword")
        let exported = try keyStore.exportMnemonic(wallet: wallet, password: "newPassword")

        XCTAssertEqual(mnemonic.bytes, exported.bytes)
    }

    func testFileName() {
        let keyStore = try! KeyStore(keyDirectory: keyDirectory)

        let timeZone = TimeZone(secondsFromGMT: -480)!
        let date = DateComponents(calendar: Calendar(identifier: .iso8601), timeZone: timeZone, year: 2018, month: 1, day: 2, hour: 20, minute: 55, second: 25, nanosecond: 186770975).date!
        let fileName = keyStore.generateFileName(identifier: keyAddress.description, date: date, timeZone: timeZone)

        XCTAssertEqual(fileName, "UTC--2018-01-02T20-55-25.186770975-0800--0x008AeEda4D805471dF9b2A5B0f38A0C3bCBA786b")
    }

    func testFileNameUTC() {
        let keyStore = try! KeyStore(keyDirectory: keyDirectory)

        let timeZone = TimeZone(abbreviation: "UTC")!
        let date = DateComponents(calendar: Calendar(identifier: .iso8601), timeZone: timeZone, year: 2018, month: 1, day: 2, hour: 20, minute: 55, second: 25, nanosecond: 186770975).date!
        let fileName = keyStore.generateFileName(identifier: keyAddress.description, date: date, timeZone: timeZone)

        XCTAssertEqual(fileName, "UTC--2018-01-02T20-55-25.186770975Z--0x008AeEda4D805471dF9b2A5B0f38A0C3bCBA786b")
    }
}
