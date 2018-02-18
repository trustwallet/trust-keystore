// Copyright © 2017-2018 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import Foundation

/// Represents a hierarchical determinisic derivation path.
public struct DerivationPath: Hashable, CustomStringConvertible {
    /// List of indices in the derivation path.
    public private(set) var indices = [Index]()

    init(indices: [Index]) {
        self.indices = indices
    }

    /// Initializes a derivation path with a string description like `m/10/0/2'/3`
    public init?(_ string: String) {
        let components = string.split(separator: "/")
        for component in components {
            if component == "m" {
                continue
            }
            if component.hasSuffix("'") {
                guard let index = Int(component.dropLast()) else {
                    return nil
                }
                indices.append(Index(index, hardened: true))
            } else {
                guard let index = Int(component) else {
                    return nil
                }
                indices.append(Index(index, hardened: false))
            }
        }
    }

    /// Increments the last index of the derivation path.
    public mutating func increment() {
        guard var last = indices.last else {
            preconditionFailure("Can't increment empty derivation path")
        }
        last.value += 1

        indices.removeLast()
        indices.append(last)
    }

    /// Returns a new derivation path with an increased last index.
    public func incremented() -> DerivationPath {
        guard var last = indices.last else {
            preconditionFailure("Can't increment empty derivation path")
        }
        last.value += 1

        var newIndices = indices
        newIndices.removeLast()
        newIndices.append(last)
        return DerivationPath(indices: newIndices)
    }

    /// String representation.
    public var description: String {
        return "m/" + indices.map({ $0.description }).joined(separator: "/")
    }

    public var hashValue: Int {
        return indices.reduce(0, { $0 ^ $1.hashValue })
    }

    public static func == (lhs: DerivationPath, rhs: DerivationPath) -> Bool {
        return lhs.indices == rhs.indices
    }
}
