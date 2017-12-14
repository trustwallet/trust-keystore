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

        XCTAssertEqual(keystore.address, "c2d7cf95645d33006175b78989035c7c9061d3f9")
        XCTAssertEqual(keystore.id, "eddd71dd-7ad6-4cd3-bc1a-11022f7db76c")
        XCTAssertEqual(keystore.version, 3)

        let header = keystore.crypto
        XCTAssertEqual(header.cipher, "aes-128-ctr")
        XCTAssertEqual(header.cipherText, "0f6d343b2a34fe571639235fc16250823c6fe3bc30525d98c41dfdf21a97aedb")
        XCTAssertEqual(header.kdf, "scrypt")
        XCTAssertEqual(header.mac, "5cf4012fffd1fbe41b122386122350c3825a709619224961a16e908c2a366aa6")
        XCTAssertEqual(header.cipherParams.iv, "cabce7fb34e4881870a2419b93f6c796")
        XCTAssertEqual(header.kdfParams.dklen, 32)
        XCTAssertEqual(header.kdfParams.n, 262144)
        XCTAssertEqual(header.kdfParams.p, 1)
        XCTAssertEqual(header.kdfParams.r, 8)
        XCTAssertEqual(header.kdfParams.salt, "1af9c4a44cf45fe6fb03dcc126fa56cb0f9e81463683dd6493fb4dc76edddd51")
    }
}
