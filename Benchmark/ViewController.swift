// Copyright © 2017 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import TrustKeystore
import UIKit

class ViewController: UIViewController {
    @IBOutlet private weak var startStopButton: UIButton!
    @IBOutlet private weak var outputTextView: UITextView!

    var running = false
    var startTime: TimeInterval = 0
    var output = ""

    @IBAction func start() {
        if running {
            return
        }

        running = true
        startStopButton.isEnabled = false
        startTime = CFAbsoluteTimeGetCurrent()
        DispatchQueue.global(qos: .userInitiated).async {
            self.run()
            DispatchQueue.main.async {
                self.stop()
            }
        }
    }

    func stop() {
        running = false
        startStopButton.isEnabled = true
    }

    func run() {
        log("Creating keystore ")
        let key = Data(hexString: "3a1076bf45ab87712ad64ccb3b10217737f7faacbf2872e88fdd9a537d8fe266")!
        let keystore = try! Keystore(password: "password", keyData: key)
        log("Decrypting keystore")
        let decrypted = try! keystore.decrypt(password: "password")
        log("Finished")
    }

    func log(_ message: String) {
        let timestamp = String(format: "%.4f", CFAbsoluteTimeGetCurrent() - startTime)
        output += "\(timestamp)s: \(message)\n"
        DispatchQueue.main.async {
            self.outputTextView.text = self.output
        }
    }
}

