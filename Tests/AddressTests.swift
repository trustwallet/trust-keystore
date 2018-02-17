// Copyright © 2017-2018 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import TrustKeystore
import XCTest

class AddressTests: XCTestCase {
    func testEIP55() {
        XCTAssertEqual(
            Address(string: "5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")!.eip55String,
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        )
        XCTAssertEqual(
            Address(string: "0x5AAEB6053F3E94C9b9A09f33669435E7Ef1BEAED")!.eip55String,
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        )
        XCTAssertEqual(
            Address(string: "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359")!.eip55String,
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
        )
        XCTAssertEqual(
            Address(string: "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB")!.eip55String,
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"
        )
        XCTAssertEqual(
            Address(string: "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb")!.eip55String,
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"
        )
    }
}
