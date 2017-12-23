// Copyright © 2017 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import Foundation

public final class Mnemonic {
    public static func encode(message: String) -> [String] {
        var out = [String]()
        let n = UInt(mnemonicWords.count)

        for i in stride(from: 0, to: message.count, by: message.count / 8) {
            let start = message.index(message.startIndex, offsetBy: i)
            let end = message.index(message.startIndex, offsetBy: i + 8)
            let x = message[start ..< end]
            let bit = strtoul(x.cString(using: .utf8), nil, 16)
            let w1 = (bit % n)
            let w2 = ((bit / n) + w1) % n
            let w3 = ((bit / n / n) + w2) % n
            out.append(mnemonicWords[Int(w1)])
            out.append(mnemonicWords[Int(w2)])
            out.append(mnemonicWords[Int(w3)])
        }
        return out
    }

    public static func decode(words: [String]) -> String? {
        var out = ""
        let n = mnemonicWords.count

        for i in stride(from: 0, to: words.count, by: 3) {
            guard let w1 = mnemonicWords.index(of: words[i]) else {
                return nil
            }
            guard let w2 = mnemonicWords.index(of: words[i+1]) else {
                return nil
            }
            guard let w3 = mnemonicWords.index(of: words[i+2]) else {
                return nil
            }

            var y = (w2 - w1) % n
            var z = (w3 - w2) % n

            if z < 0 {
                z += n
            }
            if y < 0 {
                y += n
            }
            let x = w1 + n*(y) + n*n*(z)
            out += String(format: "%08x", x)
        }
        return out
    }
}
