// Copyright © 2017-2018 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

@testable import TrustKeystore
import XCTest

class KeystoreKeyTests: XCTestCase {
    func testReadWallet() {
        let url = Bundle(for: type(of: self)).url(forResource: "key", withExtension: "json")!
        let key = try! KeystoreKey(contentsOf: url)

        XCTAssertEqual(key.address.description, "0x008AeEda4D805471dF9b2A5B0f38A0C3bCBA786b")
        XCTAssertEqual(key.id, "e13b209c-3b2f-4327-bab0-3bef2e51630d")
        XCTAssertEqual(key.version, 3)

        let header = key.crypto
        XCTAssertEqual(header.cipher, "aes-128-ctr")
        XCTAssertEqual(header.cipherText.hexString, "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c")
        XCTAssertEqual(header.kdf, "scrypt")
        XCTAssertEqual(header.mac.hexString, "2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097")
        XCTAssertEqual(header.cipherParams.iv.hexString, "83dbcc02d8ccb40e466191a123791e0e")
        XCTAssertEqual(header.kdfParams.desiredKeyLength, 32)
        XCTAssertEqual(header.kdfParams.n, 262144)
        XCTAssertEqual(header.kdfParams.p, 8)
        XCTAssertEqual(header.kdfParams.r, 1)
        XCTAssertEqual(header.kdfParams.salt.hexString, "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19")
    }

    func testReadMyEtherWallet() {
        let url = Bundle(for: type(of: self)).url(forResource: "myetherwallet", withExtension: "uu")!
        XCTAssertNoThrow(try KeystoreKey(contentsOf: url))
    }

    func testInvalidPassword() {
        let url = Bundle(for: type(of: self)).url(forResource: "key", withExtension: "json")!
        let key = try! KeystoreKey(contentsOf: url)
        XCTAssertThrowsError(try key.decrypt(password: "password")) { error in
            guard case DecryptError.invalidPassword = error else {
                XCTFail("Expected invalid password error")
                return
            }
        }
    }

    func testDecrypt() {
        let url = Bundle(for: type(of: self)).url(forResource: "key", withExtension: "json")!
        let key = try! KeystoreKey(contentsOf: url)
        let privateKey = try! key.decrypt(password: "testpassword")
        XCTAssertEqual(privateKey.hexString, "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")
    }

    func testSetAddress() {
        let privateKey = Data(hexString: "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")!
        let key = try! KeystoreKey(password: "testpassword", key: privateKey)
        XCTAssertEqual(key.address.description, "0x008AeEda4D805471dF9b2A5B0f38A0C3bCBA786b")
    }

    func testCreateWallet() {
        let privateKey = Data(hexString: "3a1076bf45ab87712ad64ccb3b10217737f7faacbf2872e88fdd9a537d8fe266")!
        let key = try! KeystoreKey(password: "password", key: privateKey)
        let decrypted = try! key.decrypt(password: "password")
        XCTAssertEqual(decrypted.hexString, privateKey.hexString)
    }

    func testSignHash() {
        let privateKey = Data(hexString: "D30519BCAE8D180DBFCC94FE0B8383DC310185B0BE97B4365083EBCECCD75759")!
        let key = try! KeystoreKey(password: "password", key: privateKey)
        let hash = Data(hexString: "3F891FDA3704F0368DAB65FA81EBE616F4AA2A0854995DA4DC0B59D2CADBD64F")!
        let result = try! key.sign(hash: hash, password: "password")

        let publicKey = Secp256k1.shared.pubicKey(from: privateKey)
        XCTAssertEqual(result.count, 65)
        XCTAssertTrue(try Secp256k1.shared.verify(signature: result, message: hash, publicKey: publicKey))
    }

    @available(iOS 10.0, *)
    func testCreateKey() {
        let password = "password"
        let key = try! KeystoreKey(password: password, type: .encryptedKey)

        let hash = Data(hexString: "3F891FDA3704F0368DAB65FA81EBE616F4AA2A0854995DA4DC0B59D2CADBD64F")!
        let result = try! key.sign(hash: hash, password: password)

        let publicKey = Secp256k1.shared.pubicKey(from: try! key.decrypt(password: password))
        XCTAssertTrue(try Secp256k1.shared.verify(signature: result, message: hash, publicKey: publicKey))
    }
}
