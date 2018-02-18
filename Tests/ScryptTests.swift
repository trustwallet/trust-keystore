// Copyright © 2017-2018 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

@testable import TrustKeystore
import XCTest

class ScryptTests: XCTestCase {

    func testCase1() {
        var params = ScryptParams()
        params.n = 1024
        params.r = 8
        params.p = 16
        params.desiredKeyLength = 64
        params.salt = "NaCl".data(using: .utf8)!

        let scrypt = Scrypt(params: params)
        let actual = try! scrypt.calculate(password: "password")

        let expected = Data(hexString: "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640")
        XCTAssertEqual(actual, expected)
    }

    func testCase2() {
        var params = ScryptParams()
        params.n = 16384
        params.r = 8
        params.p = 1
        params.desiredKeyLength = 64
        params.salt = "SodiumChloride".data(using: .utf8)!

        let scrypt = Scrypt(params: params)
        let actual = try! scrypt.calculate(password: "pleaseletmein")

        let expected = Data(hexString: "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887")
        XCTAssertEqual(actual, expected)
    }

    func testCase3() {
        var params = ScryptParams()
        params.n = 262144
        params.r = 1
        params.p = 8
        params.desiredKeyLength = 32
        params.salt = Data(hexString: "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19")!

        let scrypt = Scrypt(params: params)
        let actual = try! scrypt.calculate(password: "testpassword")

        let expected = "fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd"
        XCTAssertEqual(actual.hexString, expected)
    }

    func testInvalidDesiredKeyLength() {
        #if (arch(x86_64) || arch(arm64))
        let dklen = ((1 << 32) - 1) * 32 + 1
        XCTAssertThrowsError(try ScryptParams(salt: Data(), n: 1024, r: 1, p: 1, desiredKeyLength: dklen)) { error in
            if case ScryptParams.ValidationError.desiredKeyLengthTooLarge = error {} else {
                XCTFail("Invalid error generated: \(error)")
            }
        }
        #endif
    }

    func testZeroCostInvalid() {
        XCTAssertThrowsError(try ScryptParams(salt: Data(), n: 0, r: 1, p: 1, desiredKeyLength: 64)) { error in
            if case ScryptParams.ValidationError.invalidCostFactor = error {} else {
                XCTFail("Invalid error generated: \(error)")
            }
        }
    }

    func testOddCostInvalid() {
        XCTAssertThrowsError(try ScryptParams(salt: Data(), n: 3, r: 1, p: 1, desiredKeyLength: 64)) { error in
            if case ScryptParams.ValidationError.invalidCostFactor = error {} else {
                XCTFail("Invalid error generated: \(error)")
            }
        }
    }

    func testLargeCostInvalid() {
        XCTAssertThrowsError(try ScryptParams(salt: Data(), n: Int.max / 128, r: 8, p: 1, desiredKeyLength: 64)) { error in
            if case ScryptParams.ValidationError.invalidCostFactor = error {} else {
                XCTFail("Invalid error generated: \(error)")
            }
        }
    }

    func testLargeBlockSizeInvalid() {
        #if (arch(x86_64) || arch(arm64))
        XCTAssertThrowsError(try ScryptParams(salt: Data(), n: 1024, r: Int.max / 128 + 1, p: 1, desiredKeyLength: 64)) { error in
            if case ScryptParams.ValidationError.blockSizeTooLarge = error {} else {
                XCTFail("Invalid error generated: \(error)")
            }
        }
        #endif
    }
}
