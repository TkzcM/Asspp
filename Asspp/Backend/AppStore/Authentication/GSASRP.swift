//
//  GSASRP.swift
//  Asspp
//
//  SRP-6a client for Apple's GSA endpoints. The group is the RFC 5054 2048-bit
//  group used by Apple's native authentication protocol.
//

import Foundation

struct SRPGroup: Sendable {
    let n: APBigUInt
    let g: APBigUInt
}

enum SRPGroups {
    /// RFC 5054 Appendix A, 2048-bit group.
    static let rfc5054_2048: SRPGroup = {
        let base64 = "rGvbQTJKmpvxZt5eE4lYL69ytmUZh+4H/DGSlD21YFCjcynLtKCZ7YGT4HV3Z6E91SMSq0sDMQ3Nf0ip2gT9UOgIOWntt2ewz2CVF5oWOrNmGgX71fqq6CkYqZYvC5O4Vfl5k+yXXuqoDXQK2/T/dHNZ0EHVwz6nHSgeRGsUdzvKl7Q6I/uAFna9IHpDbGSB8dK5B4cXRhpbnTLmiPh3SFRFI7UksNV9Xqd6J3XS7PoDLPvb9S+zeGFgJ5AE5Xrmr4dOcwPOUymczAQce8MI2CpWmPOo0MOCca41+Onb+7aUtcgD2J965DXeI21SX1R1m2XjcvzWjvIPpxEfnkr/cw=="
        let data = Data(base64Encoded: base64) ?? Data()
        precondition(data.count == 256, "invalid SRP group")
        return SRPGroup(n: APBigUInt(bigEndian: data), g: APBigUInt([2]))
    }()
}

struct SRPVerifier: Sendable {
    let m1: Data
    let expectedM2: Data
    let key: Data

    func verifyServerProof(_ m2: Data) throws {
        guard m2 == expectedM2 else {
            throw GSAError.malformedResponse("server proof mismatch")
        }
    }
}

struct SRPClient: Sendable {
    let group: SRPGroup
    private let montgomery: Montgomery

    init(group: SRPGroup) {
        self.group = group
        montgomery = Montgomery(group.n)
    }

    func publicEphemeral(a: Data) -> Data {
        montgomery.power(base: group.g, exponent: APBigUInt(bigEndian: a)).bigEndianData
    }

    func processReply(
        a: Data,
        username: Data,
        password: Data,
        salt: Data,
        bPublic: Data
    ) throws -> SRPVerifier {
        let aInt = APBigUInt(bigEndian: a)
        let aPublicInt = montgomery.power(base: group.g, exponent: aInt)
        let bPublicInt = APBigUInt(bigEndian: bPublic)

        // SRP-6a safeguard against a malicious server ephemeral.
        guard !bPublicInt.isZero else {
            throw GSAError.malformedResponse("illegal server ephemeral")
        }

        let aPublicBytes = aPublicInt.bigEndianData
        let bPublicBytes = bPublicInt.bigEndianData

        let u = APBigUInt(bigEndian: GSACrypto.sha256(aPublicBytes + bPublicBytes))
        let k = computeK()
        let identityHash = GSACrypto.sha256(Data(":".utf8) + password)
        let x = APBigUInt(bigEndian: GSACrypto.sha256(salt + identityHash))

        // Stay in the Montgomery domain so the modular product does not need a
        // general-purpose division:
        //   base = B - k * g^x   (mod n)
        //   S    = base^(a + u * x) (mod n)
        let gx = montgomery.power(base: group.g, exponent: x)
        let kMontgomery = montgomery.toMontgomery(k)
        let gxMontgomery = montgomery.toMontgomery(gx)
        let product = montgomery.multiply(kMontgomery, gxMontgomery)
        let bMontgomery = montgomery.toMontgomery(bPublicInt)
        let base = montgomery.subtract(bMontgomery, product)

        let exponent = APBigUInt(APBigUInt.add(APBigUInt.multiplyRaw(u.limbs, x.limbs), aInt.limbs))
        let premaster = montgomery.fromMontgomery(montgomery.powerMontgomery(base, exponent: exponent))

        let key = GSACrypto.sha256(premaster.bigEndianData)

        let m1 = computeM1(
            aPublic: aPublicBytes,
            bPublic: bPublicBytes,
            key: key,
            username: username,
            salt: salt
        )
        let m2 = GSACrypto.sha256(aPublicBytes + m1 + key)

        return SRPVerifier(m1: m1, expectedM2: m2, key: key)
    }

    private func computeK() -> APBigUInt {
        let nBytes = group.n.bigEndianData
        let gBytes = group.g.bigEndianData
        let paddedG = Data(repeating: 0, count: max(0, nBytes.count - gBytes.count)) + gBytes
        return APBigUInt(bigEndian: GSACrypto.sha256(nBytes + paddedG))
    }

    private func computeM1(
        aPublic: Data,
        bPublic: Data,
        key: Data,
        username: Data,
        salt: Data
    ) -> Data {
        let nBytes = group.n.bigEndianData
        let gBytes = group.g.bigEndianData
        let paddedG = Data(repeating: 0, count: max(0, nBytes.count - gBytes.count)) + gBytes

        let gHash = GSACrypto.sha256(paddedG)
        let nHash = GSACrypto.sha256(nBytes)
        let xored = Data(zip(gHash, nHash).map { $0 ^ $1 })
        let userHash = GSACrypto.sha256(username)

        return GSACrypto.sha256(xored + userHash + salt + aPublic + bPublic + key)
    }
}
