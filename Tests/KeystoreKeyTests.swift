// Copyright © 2017-2018 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import TrustCore
@testable import TrustKeystore
import XCTest

class KeystoreKeyTests: XCTestCase {
    func testReadWallet() {
        let url = Bundle(for: type(of: self)).url(forResource: "key", withExtension: "json")!
        let key = try! KeystoreKey(contentsOf: url)

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

    func testCreateWallet() {
        let privateKey = PrivateKey(data: Data(hexString: "3a1076bf45ab87712ad64ccb3b10217737f7faacbf2872e88fdd9a537d8fe266")!)!
        let key = try! KeystoreKey(password: "password", key: privateKey, coin: nil)
        let decrypted = try! key.decrypt(password: "password")

        XCTAssertEqual(decrypted.hexString, privateKey.data.hexString)
    }

    func testDecodingEthereumAddress() {
        let url = Bundle(for: type(of: self)).url(forResource: "key", withExtension: "json")!
        let key = try! KeystoreKey(contentsOf: url)

        XCTAssertTrue(key.address is EthereumAddress)
        XCTAssertEqual(key.address?.description, "0x008AeEda4D805471dF9b2A5B0f38A0C3bCBA786b")
    }

    func testDecodingBitcoinAddress() {
        let url = Bundle(for: type(of: self)).url(forResource: "key_bitcoin", withExtension: "json")!
        let key = try! KeystoreKey(contentsOf: url)

        XCTAssertTrue(key.address is BitcoinAddress)
        XCTAssertEqual(key.address?.description, "3PWazDi9n1Hfyq9gXFxDxzADNL8RNYyK2y")
    }

    func testBitcoinAddress() {
        let address = KeystoreKey.address(for: Bitcoin().coinType, addressString: "3PWazDi9n1Hfyq9gXFxDxzADNL8RNYyK2y")

        XCTAssertTrue(address is BitcoinAddress)
        XCTAssertEqual(address?.description, "3PWazDi9n1Hfyq9gXFxDxzADNL8RNYyK2y")
    }

    func testFormatEthereumAddress() {
        let address = KeystoreKey.address(for: Ethereum().coinType, addressString: "0x008AeEda4D805471dF9b2A5B0f38A0C3bCBA786b")

        XCTAssertTrue(address is EthereumAddress)
        XCTAssertEqual(address?.description, "0x008AeEda4D805471dF9b2A5B0f38A0C3bCBA786b")
    }

    func testFormatVechainAddress() {
        let address = KeystoreKey.address(for: Vechain().coinType, addressString: "0x008AeEda4D805471dF9b2A5B0f38A0C3bCBA786b")

        XCTAssertTrue(address is EthereumAddress)
        XCTAssertEqual(address?.description, "0x008AeEda4D805471dF9b2A5B0f38A0C3bCBA786b")
    }

    func testFormatTronAddress() {
        let address = KeystoreKey.address(for: Tron().coinType, addressString: "TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW")

        XCTAssertTrue(address is BitcoinAddress)
        XCTAssertEqual(address?.description, "TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW")
    }
}
