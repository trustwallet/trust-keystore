// Copyright © 2017 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

@testable import TrustKeystore
import XCTest

class DerivationPathTests: XCTestCase {
    func testInit() {
        let path = DerivationPath("m/44'/60'/0'/0")
        XCTAssertNotNil(path)
        XCTAssertEqual(path?.indices[0], DerivationPath.Index(44, hardened: true))
        XCTAssertEqual(path?.indices[1], DerivationPath.Index(60, hardened: true))
        XCTAssertEqual(path?.indices[2], DerivationPath.Index(0, hardened: true))
        XCTAssertEqual(path?.indices[3], DerivationPath.Index(0, hardened: false))
    }

    func testInitInvalid() {
        XCTAssertNil(DerivationPath("a/b/c"))
        XCTAssertNil(DerivationPath("m/44'/60''/"))
    }

    func testDescription() {
        let path = DerivationPath("m/44'/60'/0'/0")
        XCTAssertEqual(path?.description, "m/44'/60'/0'/0")
    }

    func testIncrement() {
        let path = DerivationPath("m/44'/60'/0'/0")
        let newPath = path?.incremented()
        XCTAssertEqual(newPath?.description, "m/44'/60'/0'/1")
    }

    func testIncremented() {
        var path = DerivationPath("m/44'/60'/0'/0")
        path?.increment()
        XCTAssertEqual(path?.description, "m/44'/60'/0'/1")
    }

    func testEqual() {
        let path1 = DerivationPath("m/44'/60'/0'/0")
        let path2 = DerivationPath("44'/60'/0'/0")
        XCTAssertNotNil(path1)
        XCTAssertNotNil(path2)
        XCTAssertEqual(path1, path2)
    }
}
