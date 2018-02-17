// Copyright © 2017-2018 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import TrustKeystore
import XCTest

class MnemonicTests: XCTestCase {
    func testDeriveSeed() {
        let mnemonic = "often tobacco bread scare imitate song kind common bar forest yard wisdom"
        let password = "testtest123"
        let seed = Data(hexString: "b4186ab8ac0ebfd3c20f992d0b602639fe59f0e4d2e66dea487194580e0aa0031387c9f30488a7628ed7350a63dd97e1acb259896082e3b34a1ff0dd85c287d1")

        XCTAssertEqual(Mnemonic.deriveSeed(mnemonic: mnemonic, password: password), seed)
    }

    func testEncode() {
        let message = "c61d43dc5bb7a4e754d111dae8105b6f25356492df5e50ecb33b858d94f8c338"
        let expected = "ship tube warfare resist kid inhale fashion captain sustain dog bitter tattoo fashion rather enter type extend grain solve arch sun ladder artefact bronze"
        let words = Mnemonic.generate(from: Data(hexString: message)!)
        XCTAssertEqual(words, expected)
    }

    func testValid() {
        let mnemonic = "ship tube warfare resist kid inhale fashion captain sustain dog bitter tattoo fashion rather enter type extend grain solve arch sun ladder artefact bronze"
        XCTAssertTrue(Mnemonic.isValid(mnemonic))
    }

    func testInvalid() {
        let mnemonic = "ship turd warfare resist kid inhale fashion captain sustain dog bitter tattoo fashion rather enter type extend grain solve arch sun ladder artefact bronze"
        XCTAssertFalse(Mnemonic.isValid(mnemonic))
    }
}
