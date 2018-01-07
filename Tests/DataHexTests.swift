// Copyright © 2017 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

@testable import TrustKeystore
import XCTest

class DataHexTests: XCTestCase {
    func testDataToHex() {
        let data = Data(bytes: [0xDE, 0xAD, 0xBE, 0xEF])
        XCTAssertEqual(data.hexString, "deadbeef")
    }

    func testHexToData() {
        let data = Data(hexString: "deadbeef")!
        XCTAssertEqual(data, Data(bytes: [0xDE, 0xAD, 0xBE, 0xEF]))
    }

    func testHexWithPrefixToData() {
        let data = Data(hexString: "0xdeadbeef")!
        XCTAssertEqual(data, Data(bytes: [0xDE, 0xAD, 0xBE, 0xEF]))
    }

    func testInvalidHexToData() {
        let data = Data(hexString: "invalid")
        XCTAssertNil(data)
    }

    func testShortHexToData() {
        let data = Data(hexString: "0x1")!
        XCTAssertEqual(data.hexString, "01")
    }
}
