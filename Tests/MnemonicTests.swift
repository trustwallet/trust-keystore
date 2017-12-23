// Copyright © 2017 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import TrustKeystore
import XCTest

class MnemonicTests: XCTestCase {
    func testDecode() {
        let words: [String] = [
            "ink",
            "balance",
            "gain",
            "fear",
            "happen",
            "melt",
            "mom",
            "surface",
            "stir",
            "bottle",
            "unseen",
            "expression",
            "important",
            "curl",
            "grant",
            "fairy",
            "across",
            "back",
            "figure",
            "breast",
            "nobody",
            "scratch",
            "worry",
            "yesterday",
        ]
        let expected = "c61d43dc5bb7a4e754d111dae8105b6f25356492df5e50ecb33b858d94f8c338"
        let result = Mnemonic.decode(words: words)
        XCTAssertEqual(result, expected)
    }

    func testEncode() {
        let message = "c61d43dc5bb7a4e754d111dae8105b6f25356492df5e50ecb33b858d94f8c338"
        let expected: [String] = [
            "ink",
            "balance",
            "gain",
            "fear",
            "happen",
            "melt",
            "mom",
            "surface",
            "stir",
            "bottle",
            "unseen",
            "expression",
            "important",
            "curl",
            "grant",
            "fairy",
            "across",
            "back",
            "figure",
            "breast",
            "nobody",
            "scratch",
            "worry",
            "yesterday",
        ]
        let words = Mnemonic.encode(message: message)
        XCTAssertEqual(words, expected)
    }
}
