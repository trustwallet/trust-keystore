// Copyright © 2017 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

@testable import TrustKeystore
import XCTest

class TrustKeystoreTests: XCTestCase {
    func testReadWallet() {
        let url = Bundle(for: type(of: self)).url(forResource: "wallet", withExtension: "json")!
        let keystore = try! Keystore(contentsOf: url)

        XCTAssertEqual(keystore.address, "008aeeda4d805471df9b2a5b0f38a0c3bcba786b")
        XCTAssertEqual(keystore.id, "e13b209c-3b2f-4327-bab0-3bef2e51630d")
        XCTAssertEqual(keystore.version, 3)

        let header = keystore.crypto
        XCTAssertEqual(header.cipher, "aes-128-ctr")
        XCTAssertEqual(header.cipherText.hexString, "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c")
        XCTAssertEqual(header.kdf, "scrypt")
        XCTAssertEqual(header.mac.hexString, "2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097")
        XCTAssertEqual(header.cipherParams.iv.hexString, "83dbcc02d8ccb40e466191a123791e0e")
        XCTAssertEqual(header.kdfParams.derivedKeyLength, 32)
        XCTAssertEqual(header.kdfParams.n, 262144)
        XCTAssertEqual(header.kdfParams.p, 8)
        XCTAssertEqual(header.kdfParams.r, 1)
        XCTAssertEqual(header.kdfParams.salt.hexString, "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19")
    }

    func testInvalidPassword() {
        let url = Bundle(for: type(of: self)).url(forResource: "wallet", withExtension: "json")!
        let keystore = try! Keystore(contentsOf: url)
        XCTAssertThrowsError(try keystore.decrypt(password: "password")) { error in
            guard case DecryptError.invalidPassword = error else {
                XCTFail("Expected invalid password error")
                return
            }
        }
    }

    func testDecrypt() {
        let url = Bundle(for: type(of: self)).url(forResource: "wallet", withExtension: "json")!
        let keystore = try! Keystore(contentsOf: url)
        let key = try! keystore.decrypt(password: "testpassword")
        XCTAssertEqual(key.hexString, "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")
    }

    func testSetAddress() {
        let key = Data(hexString: "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")!
        let keystore = try! Keystore(password: "testpassword", key: key)
        XCTAssertEqual(keystore.address, "008aeeda4d805471df9b2a5b0f38a0c3bcba786b")
    }

    func testCreateWallet() {
        let key = Data(hexString: "3a1076bf45ab87712ad64ccb3b10217737f7faacbf2872e88fdd9a537d8fe266")!
        let keystore = try! Keystore(password: "password", key: key)
        let decrypted = try! keystore.decrypt(password: "password")
        XCTAssertEqual(decrypted.hexString, key.hexString)
    }
}
