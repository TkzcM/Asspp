//
//  GSAAnisette.swift
//  Asspp
//
//  Anisette data is a set of device-attestation headers required by Apple's
//  Grand Slam Authentication (GSA) endpoints. Non-jailbroken iOS cannot mint
//  them locally, so they are fetched from a remote anisette-v3-server.
//

import Foundation

struct GSAAnisette: Sendable {
    let headers: [String: String]
    let generatedAt: Date

    var needsRefresh: Bool { Date().timeIntervalSince(generatedAt) > 60 }
    var isValid: Bool { Date().timeIntervalSince(generatedAt) < 90 }

    func headerValue(for name: String) -> String? {
        if let value = headers[name] { return value }
        let lowered = name.lowercased()
        return headers.first { $0.key.lowercased() == lowered }?.value
    }

    /// Device headers sent with every GSA request.
    func requestHeaders() throws -> [String: String] {
        guard isValid else { throw GSAError.anisetteUnavailable("stale anisette data") }
        return headers
    }

    /// `cpd` payload embedded in the SRP init/complete requests.
    func cpd() throws -> [String: String] {
        guard isValid else { throw GSAError.anisetteUnavailable("stale anisette data") }

        var result = headers
        result["bootstrap"] = "true"
        result["icscrec"] = "true"
        result["loc"] = "en_GB"
        result["pbe"] = "false"
        result["prkgen"] = "true"
        result["svct"] = "iCloud"
        return result
    }

    /// Headers for the 2FA verification endpoints.
    func twoFactorHeaders() throws -> [String: String] {
        guard isValid else { throw GSAError.anisetteUnavailable("stale anisette data") }

        var result = headers
        if let clientInfo = headerValue(for: "X-Mme-Client-Info") {
            result["X-Mme-Client-Info"] = clientInfo
        }
        result["X-Apple-App-Info"] = "com.apple.gs.xcode.auth"
        result["X-Xcode-Version"] = "11.2 (11B41)"
        return result
    }
}

protocol GSAAnisetteProviding: Sendable {
    func anisette() async throws -> GSAAnisette
}

actor RemoteAnisetteProvider: GSAAnisetteProviding {
    private let serverURL: URL
    private var cached: GSAAnisette?

    init(serverURL: URL) {
        self.serverURL = serverURL
    }

    func anisette() async throws -> GSAAnisette {
        if let cached, !cached.needsRefresh { return cached }
        let fetched = try await fetch()
        cached = fetched
        return fetched
    }

    private func fetch() async throws -> GSAAnisette {
        var request = URLRequest(url: serverURL)
        request.httpMethod = "GET"
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.timeoutInterval = 15

        let (data, response) = try await URLSession.shared.data(for: request)
        if let http = response as? HTTPURLResponse, !(200 ... 299).contains(http.statusCode) {
            throw GSAError.anisetteUnavailable("server returned HTTP \(http.statusCode)")
        }

        guard let object = try? JSONSerialization.jsonObject(with: data),
              let dictionary = object as? [String: Any]
        else {
            throw GSAError.anisetteUnavailable("unexpected response")
        }

        var headers: [String: String] = [:]
        for (key, value) in dictionary {
            guard let string = value as? String else { continue }
            headers[key] = string
        }
        guard !headers.isEmpty else {
            throw GSAError.anisetteUnavailable("empty response")
        }

        return GSAAnisette(headers: headers, generatedAt: Date())
    }
}
