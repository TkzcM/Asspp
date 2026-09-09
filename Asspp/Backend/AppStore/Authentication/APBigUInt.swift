//
//  APBigUInt.swift
//  Asspp
//
//  Minimal big-endian unsigned integer backed by little-endian 32-bit limbs,
//  with Montgomery modular exponentiation. Apple's GSA SRP exchange needs
//  2048-bit modexp, and adding a BigInt dependency to the app target is not
//  worth it for the handful of operations the login flow performs.
//

import Foundation

struct APBigUInt: Equatable, CustomStringConvertible, Sendable {
    /// Little-endian limbs with no trailing zero limbs. Zero is `[]`.
    private(set) var limbs: [UInt32]

    init(_ limbs: [UInt32]) {
        var value = limbs
        while let last = value.last, last == 0 { value.removeLast() }
        self.limbs = value
    }

    static let zero = APBigUInt([])
    static let one = APBigUInt([1])

    var isZero: Bool { limbs.isEmpty }

    init(bigEndian data: Data) {
        let bytes = [UInt8](data)
        var words: [UInt32] = []
        var index = bytes.count
        while index > 0 {
            let start = max(0, index - 4)
            var word: UInt32 = 0
            for i in start ..< index { word = (word << 8) | UInt32(bytes[i]) }
            words.append(word)
            index = start
        }
        self.init(words)
    }

    /// Minimal big-endian representation. Zero serializes to a single 0 byte,
    /// matching the SRP reference implementations Asspp interoperates with.
    var bigEndianData: Data {
        guard !limbs.isEmpty else { return Data([0]) }
        var bytes: [UInt8] = []
        for (index, limb) in limbs.enumerated().reversed() {
            let word: [UInt8] = [
                UInt8((limb >> 24) & 0xff),
                UInt8((limb >> 16) & 0xff),
                UInt8((limb >> 8) & 0xff),
                UInt8(limb & 0xff),
            ]
            if index == limbs.count - 1 {
                var started = false
                for byte in word {
                    if byte != 0 { started = true }
                    if started { bytes.append(byte) }
                }
            } else {
                bytes.append(contentsOf: word)
            }
        }
        return Data(bytes)
    }

    func limb(_ index: Int) -> UInt32 { index < limbs.count ? limbs[index] : 0 }

    var description: String { bigEndianData.map { String(format: "%02x", $0) }.joined() }

    var bitWidth: Int {
        guard let top = limbs.last else { return 0 }
        return (limbs.count - 1) * 32 + (32 - top.leadingZeroBitCount)
    }

    func bit(at index: Int) -> Bool {
        let limbIndex = index / 32
        guard limbIndex < limbs.count else { return false }
        return (limbs[limbIndex] >> UInt32(index % 32)) & 1 == 1
    }

    static func compare(_ lhs: [UInt32], _ rhs: [UInt32]) -> Int {
        if lhs.count != rhs.count { return lhs.count < rhs.count ? -1 : 1 }
        var index = lhs.count - 1
        while index >= 0 {
            if lhs[index] != rhs[index] { return lhs[index] < rhs[index] ? -1 : 1 }
            index -= 1
        }
        return 0
    }

    /// `lhs - rhs` assuming `lhs >= rhs`.
    static func subtract(_ lhs: [UInt32], _ rhs: [UInt32]) -> [UInt32] {
        var out = lhs
        var borrow: Int64 = 0
        for index in 0 ..< out.count {
            let value = index < rhs.count ? Int64(rhs[index]) : 0
            var current = Int64(out[index]) - value - borrow
            if current < 0 {
                current += Int64(1) << 32
                borrow = 1
            } else {
                borrow = 0
            }
            out[index] = UInt32(truncatingIfNeeded: current)
        }
        return out
    }

    /// `lhs + rhs`, not reduced. Callers normalize via `APBigUInt`.
    static func add(_ lhs: [UInt32], _ rhs: [UInt32]) -> [UInt32] {
        let count = max(lhs.count, rhs.count)
        var out = [UInt32](repeating: 0, count: count + 1)
        var carry: UInt64 = 0
        for index in 0 ..< count {
            let left = index < lhs.count ? UInt64(lhs[index]) : 0
            let right = index < rhs.count ? UInt64(rhs[index]) : 0
            let current = left + right + carry
            out[index] = UInt32(truncatingIfNeeded: current)
            carry = current >> 32
        }
        out[count] = UInt32(truncatingIfNeeded: carry)
        return out
    }

    /// Schoolbook product. The caller is expected to normalize via `APBigUInt`.
    static func multiplyRaw(_ lhs: [UInt32], _ rhs: [UInt32]) -> [UInt32] {
        var out = [UInt32](repeating: 0, count: lhs.count + rhs.count + 1)
        for i in 0 ..< lhs.count {
            var carry: UInt64 = 0
            let left = UInt64(lhs[i])
            for j in 0 ..< rhs.count {
                let current = UInt64(out[i + j]) + left * UInt64(rhs[j]) + carry
                out[i + j] = UInt32(truncatingIfNeeded: current)
                carry = current >> 32
            }
            var k = i + rhs.count
            while carry > 0 {
                let current = UInt64(out[k]) + carry
                out[k] = UInt32(truncatingIfNeeded: current)
                carry = current >> 32
                k += 1
            }
        }
        return out
    }
}

/// Montgomery arithmetic modulo an odd modulus.
struct Montgomery: Sendable {
    let modulus: [UInt32]
    /// `-modulus[0]^{-1} mod 2^32`
    let nPrime: UInt32
    let limbCount: Int
    /// `R^2 mod n`, cached because every conversion to Montgomery form needs it.
    let rSquared: [UInt32]

    init(_ n: APBigUInt) {
        precondition(!n.isZero && (n.limb(0) & 1) == 1, "Montgomery modulus must be odd")
        modulus = n.limbs
        limbCount = n.limbs.count

        var inverse: UInt32 = 1
        for _ in 0 ..< 5 {
            inverse = inverse &* (2 &- (n.limb(0) &* inverse))
        }
        nPrime = 0 &- inverse

        var value: [UInt32] = [1]
        for _ in 0 ..< (64 * limbCount) { value = Montgomery.doubleModulo(value, modulus: modulus) }
        rSquared = value
    }

    private static func doubleModulo(_ value: [UInt32], modulus: [UInt32]) -> [UInt32] {
        var out = [UInt32](repeating: 0, count: value.count + 1)
        var carry: UInt64 = 0
        for i in 0 ..< value.count {
            let current = UInt64(value[i]) * 2 + carry
            out[i] = UInt32(truncatingIfNeeded: current)
            carry = current >> 32
        }
        out[value.count] = UInt32(truncatingIfNeeded: carry)
        while let last = out.last, last == 0 { out.removeLast() }
        if APBigUInt.compare(out, modulus) >= 0 {
            out = APBigUInt.subtract(out, modulus)
        }
        return out
    }

    /// REDC: given `T < n * R`, returns `T * R^{-1} mod n` with `R = 2^(32*limbCount)`.
    func reduce(_ product: [UInt32]) -> [UInt32] {
        var t = product
        if t.count < 2 * limbCount + 1 {
            t += [UInt32](repeating: 0, count: 2 * limbCount + 1 - t.count)
        }

        for i in 0 ..< limbCount {
            let factor = UInt32(truncatingIfNeeded: UInt64(t[i]) &* UInt64(nPrime))
            var carry: UInt64 = 0
            for j in 0 ..< limbCount {
                let current = UInt64(t[i + j]) + UInt64(factor) * UInt64(modulus[j]) + carry
                t[i + j] = UInt32(truncatingIfNeeded: current)
                carry = current >> 32
            }
            var k = i + limbCount
            while carry > 0 {
                let current = UInt64(t[k]) + carry
                t[k] = UInt32(truncatingIfNeeded: current)
                carry = current >> 32
                k += 1
            }
        }

        var out = Array(t[limbCount...])
        while let last = out.last, last == 0 { out.removeLast() }
        while APBigUInt.compare(out, modulus) >= 0 {
            out = APBigUInt.subtract(out, modulus)
            while let last = out.last, last == 0 { out.removeLast() }
        }
        if out.count > limbCount { out = Array(out.prefix(limbCount)) }
        return out
    }

    /// `lhs * rhs * R^{-1} mod n`
    func multiply(_ lhs: [UInt32], _ rhs: [UInt32]) -> [UInt32] {
        reduce(APBigUInt.multiplyRaw(lhs, rhs))
    }

    func toMontgomery(_ value: APBigUInt) -> [UInt32] {
        multiply(value.limbs, rSquared)
    }

    func fromMontgomery(_ value: [UInt32]) -> APBigUInt {
        APBigUInt(multiply(value, [1]))
    }

    /// `(lhs - rhs) mod n` for values already reduced modulo n.
    func subtract(_ lhs: [UInt32], _ rhs: [UInt32]) -> [UInt32] {
        if APBigUInt.compare(lhs, rhs) >= 0 {
            return APBigUInt.subtract(lhs, rhs)
        }
        let wrapped = APBigUInt.add(lhs, modulus)
        return APBigUInt.subtract(wrapped, rhs)
    }

    /// Modular exponentiation for a value in the Montgomery domain.
    func powerMontgomery(_ base: [UInt32], exponent: APBigUInt) -> [UInt32] {
        var accumulator = toMontgomery(.one)
        var factor = base
        for index in 0 ..< exponent.bitWidth {
            if exponent.bit(at: index) { accumulator = multiply(accumulator, factor) }
            factor = multiply(factor, factor)
        }
        return accumulator
    }

    /// `base^exponent mod n` for a plain (non-Montgomery) base.
    func power(base: APBigUInt, exponent: APBigUInt) -> APBigUInt {
        let converted = toMontgomery(base)
        return fromMontgomery(powerMontgomery(converted, exponent: exponent))
    }
}
