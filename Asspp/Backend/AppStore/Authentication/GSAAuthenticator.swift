//
//  GSAAuthenticator.swift
//  Asspp
//
//  Apple ID sign-in through Apple's Grand Slam Authentication (GSA) endpoints.
//  The legacy `MZFinance.woa/wa/authenticate` endpoint now answers every
//  third-party client with HTTP 403, so Asspp falls back to the SRP flow that
//  Xcode itself uses. Non-jailbroken iOS cannot produce the required anisette
//  headers locally, so they are fetched from a remote anisette-v3-server.
//

import ApplePackage
import Foundation
import Security

enum GSAAuthenticator {
    private static let gsaEndpoint = URL(string: "https://gsa.apple.com/grandslam/GsService2")!
    private static let validateEndpoint = URL(string: "https://gsa.apple.com/grandslam/GsService2/validate")!
    private static let trustedDeviceEndpoint = URL(string: "https://gsa.apple.com/auth/verify/trusteddevice")!
    private static let authEndpoint = URL(string: "https://gsa.apple.com/auth")!
    private static let verifyPhoneEndpoint = URL(string: "https://gsa.apple.com/auth/verify/phone/")!
    private static let verifyPhoneCodeEndpoint = URL(string: "https://gsa.apple.com/auth/verify/phone/securitycode")!

    private static let userAgent = "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0"

    // MARK: - Public entry point

    static func authenticate(
        email: String,
        password: String,
        code: String,
        anisetteServerURL: URL
    ) async throws -> ApplePackage.Account {
        let provider = RemoteAnisetteProvider(serverURL: anisetteServerURL)

        var session = try await loginEmailPassword(
            email: email,
            password: password,
            provider: provider
        )

        switch session.state {
        case .loggedIn:
            break

        case .needsTrustedDevice2FA:
            guard !code.isEmpty else {
                _ = try? await requestTrustedDeviceCode(session: session, provider: provider)
                throw GSAError.twoFactorRequired("""
                Authentication requires a verification code.
                Approve the sign-in on one of your Apple devices, then enter the displayed code.
                """)
            }
            try await verifyTrustedDevice(code: code, session: session, provider: provider)
            session = try await loginEmailPassword(email: email, password: password, provider: provider)

        case .needsSMS2FA:
            let extras = try await fetchAuthExtras(session: session, provider: provider)
            guard let phone = extras.trustedPhoneNumbers.first else {
                throw GSAError.malformedResponse("no trusted phone numbers")
            }
            let verifyBody = VerifyBody(phoneNumber: .init(id: phone.id), mode: "sms", securityCode: nil)
            guard !code.isEmpty else {
                try await requestSMSCode(verifyBody: verifyBody, session: session, provider: provider)
                throw GSAError.twoFactorRequired("""
                Authentication requires an SMS verification code.
                Request the code on your Apple ID sign-in prompt, then enter it here.
                """)
            }
            try await verifySMSCode(code: code, verifyBody: verifyBody, session: session, provider: provider)
            session = try await loginEmailPassword(email: email, password: password, provider: provider)

        case let .needsExtraStep(step):
            throw GSAError.malformedResponse("additional authentication step required: \(step)")
        }

        guard case .loggedIn = session.state else {
            throw GSAError.malformedResponse("unexpected login state")
        }

        return try buildAccount(email: email, password: password, spd: session.spd)
    }

    // MARK: - Session model

    private struct SPD {
        let dsid: String
        let idmsToken: String
        let firstName: String
        let lastName: String
        let passwordToken: String?
        let storeFront: String?
    }

    private struct Session {
        enum State {
            case loggedIn
            case needsTrustedDevice2FA
            case needsSMS2FA
            case needsExtraStep(String)
        }

        let spd: SPD
        let state: State
    }

    // MARK: - SRP login

    private static func loginEmailPassword(
        email: String,
        password: String,
        provider: RemoteAnisetteProvider
    ) async throws -> Session {
        let srp = SRPClient(group: SRPGroups.rfc5054_2048)
        let a = try randomBytes(count: 32)
        let aPublic = srp.publicEphemeral(a: a)

        let anisette = try await provider.anisette()
        let cpd = try anisette.cpd()

        var headers = try anisette.requestHeaders()
        headers["Content-Type"] = "text/x-xml-plist"
        headers["Accept"] = "*/*"
        headers["User-Agent"] = userAgent

        let initResponse = try await sendPlistRequest(
            url: gsaEndpoint,
            method: "POST",
            headers: headers,
            body: [
                "Header": ["Version": "1.0.1"],
                "Request": [
                    "A2k": aPublic,
                    "cpd": cpd,
                    "o": "init",
                    "ps": ["s2k", "s2k_fo"],
                    "u": email,
                ],
            ]
        )
        try checkServiceError(initResponse)

        guard let salt = initResponse["s"] as? Data,
              let bPublic = initResponse["B"] as? Data,
              let iterations = integer(initResponse["i"]),
              let challenge = initResponse["c"] as? String
        else {
            throw GSAError.malformedResponse("missing init parameters")
        }
        guard iterations > 0 else {
            throw GSAError.malformedResponse("invalid iteration count")
        }

        let protocolName = initResponse["sp"] as? String ?? "s2k"
        let passwordKey = try derivePasswordKey(
            password: password,
            salt: salt,
            iterations: iterations,
            protocolName: protocolName
        )

        let verifier = try srp.processReply(
            a: a,
            username: Data(email.utf8),
            password: passwordKey,
            salt: salt,
            bPublic: bPublic
        )

        let completeResponse = try await sendPlistRequest(
            url: gsaEndpoint,
            method: "POST",
            headers: headers,
            body: [
                "Header": ["Version": "1.0.1"],
                "Request": [
                    "M1": verifier.m1,
                    "cpd": cpd,
                    "c": challenge,
                    "o": "complete",
                    "u": email,
                ],
            ]
        )
        try checkServiceError(completeResponse)

        guard let m2 = completeResponse["M2"] as? Data else {
            throw GSAError.malformedResponse("missing server proof")
        }
        try verifier.verifyServerProof(m2)

        guard let encryptedSPD = completeResponse["spd"] as? Data else {
            throw GSAError.malformedResponse("missing SPD")
        }

        let spdDictionary = try decryptSPD(encryptedSPD, sessionKey: verifier.key)
        let spd = try decodeSPD(spdDictionary)

        let state: Session.State = {
            guard let status = completeResponse["Status"] as? [String: Any],
                  let authType = status["au"] as? String
            else { return .loggedIn }
            switch authType {
            case "trustedDeviceSecondaryAuth": return .needsTrustedDevice2FA
            case "secondaryAuth": return .needsSMS2FA
            default: return .needsExtraStep(authType)
            }
        }()

        return Session(spd: spd, state: state)
    }

    private static func derivePasswordKey(
        password: String,
        salt: Data,
        iterations: Int,
        protocolName: String
    ) throws -> Data {
        let hashed = GSACrypto.sha256(Data(password.utf8))
        let pbkdfPassword = protocolName == "s2k_fo" ? Data(hashed.hexLowercased.utf8) : hashed
        return try GSACrypto.pbkdf2SHA256(
            password: pbkdfPassword,
            salt: salt,
            iterations: iterations,
            keyLength: 32
        )
    }

    private static func decryptSPD(_ ciphertext: Data, sessionKey: Data) throws -> [String: Any] {
        let extraDataKey = GSACrypto.hmacSHA256(key: sessionKey, message: Data("extra data key:".utf8))
        let extraDataIV = GSACrypto.hmacSHA256(key: sessionKey, message: Data("extra data iv:".utf8))
        let plaintext = try GSACrypto.aes256CBCDecrypt(
            ciphertext,
            key: extraDataKey,
            iv: Data(extraDataIV.prefix(16))
        )
        guard let plist = try PropertyListSerialization.propertyList(from: plaintext, options: [], format: nil) as? [String: Any] else {
            throw GSAError.malformedResponse("invalid SPD")
        }
        return plist
    }

    private static func decodeSPD(_ spd: [String: Any]) throws -> SPD {
        guard let dsid = spd["adsid"] as? String, !dsid.isEmpty else {
            throw GSAError.malformedResponse("missing adsid")
        }
        guard let token = spd["GsIdmsToken"] as? String, !token.isEmpty else {
            throw GSAError.malformedResponse("missing GsIdmsToken")
        }

        return SPD(
            dsid: dsid,
            idmsToken: token,
            firstName: (spd["fn"] as? String) ?? "",
            lastName: (spd["ln"] as? String) ?? "",
            passwordToken: extractPasswordToken(from: spd),
            storeFront: resolveStoreFront(from: spd)
        )
    }

    private static func extractPasswordToken(from spd: [String: Any]) -> String? {
        if let tokens = spd["t"] as? [String: Any],
           let pet = tokens["com.apple.gs.idms.pet"] as? [String: Any],
           let token = pet["token"] as? String
        {
            return token
        }
        if let token = spd["token"] as? String { return token }
        if let token = spd["passwordToken"] as? String { return token }
        return nil
    }

    private static func resolveStoreFront(from spd: [String: Any]) -> String {
        if let store = spd["sf"] as? String, !store.isEmpty { return store }
        if let store = spd["storeFront"] as? String, !store.isEmpty { return store }
        let region = Locale.current.region?.identifier ?? "US"
        return ApplePackage.Configuration.storeId(for: region) ?? "143441"
    }

    // MARK: - 2FA

    private struct AuthenticationExtras: Decodable {
        struct TrustedPhoneNumber: Decodable {
            let id: Int
            let numberWithDialCode: String?
            let lastTwoDigits: String?
        }

        let trustedPhoneNumbers: [TrustedPhoneNumber]
    }

    private struct VerifyBody: Encodable {
        struct PhoneNumber: Encodable { let id: Int }
        struct SecurityCode: Encodable { let code: String }

        let phoneNumber: PhoneNumber
        let mode: String
        var securityCode: SecurityCode?
    }

    private static func requestTrustedDeviceCode(
        session: Session,
        provider: RemoteAnisetteProvider
    ) async throws {
        let headers = try await twoFactorHeaders(session: session, provider: provider, sms: false)
        _ = try await sendRawRequest(url: trustedDeviceEndpoint, method: "GET", headers: headers, body: nil)
    }

    private static func verifyTrustedDevice(
        code: String,
        session: Session,
        provider: RemoteAnisetteProvider
    ) async throws {
        var headers = try await twoFactorHeaders(session: session, provider: provider, sms: false)
        headers["security-code"] = code
        let data = try await sendRawRequest(url: validateEndpoint, method: "GET", headers: headers, body: nil)
        try checkServiceError(try parsePlist(data))
    }

    private static func requestSMSCode(
        verifyBody: VerifyBody,
        session: Session,
        provider: RemoteAnisetteProvider
    ) async throws {
        var headers = try await twoFactorHeaders(session: session, provider: provider, sms: true)
        headers["Accept"] = "application/json"
        _ = try await sendRawRequest(
            url: verifyPhoneEndpoint,
            method: "POST",
            headers: headers,
            body: try JSONEncoder().encode(verifyBody)
        )
    }

    private static func verifySMSCode(
        code: String,
        verifyBody: VerifyBody,
        session: Session,
        provider: RemoteAnisetteProvider
    ) async throws {
        var body = verifyBody
        body.securityCode = .init(code: code)

        var headers = try await twoFactorHeaders(session: session, provider: provider, sms: true)
        headers["Accept"] = "application/json"
        do {
            _ = try await sendRawRequest(
                url: verifyPhoneCodeEndpoint,
                method: "POST",
                headers: headers,
                body: try JSONEncoder().encode(body)
            )
        } catch let error as GSAError {
            if case .invalidTwoFactorCode = error { throw error }
            throw GSAError.invalidTwoFactorCode
        }
    }

    private static func fetchAuthExtras(
        session: Session,
        provider: RemoteAnisetteProvider
    ) async throws -> AuthenticationExtras {
        var headers = try await twoFactorHeaders(session: session, provider: provider, sms: true)
        headers["Accept"] = "application/json"
        // Apple answers HTTP 423 with the trusted-phone list in the body.
        let data = try await sendRawRequest(
            url: authEndpoint,
            method: "GET",
            headers: headers,
            body: nil,
            acceptableStatusCodes: [201, 423]
        )
        return try JSONDecoder().decode(AuthenticationExtras.self, from: data)
    }

    private static func twoFactorHeaders(
        session: Session,
        provider: RemoteAnisetteProvider,
        sms: Bool
    ) async throws -> [String: String] {
        let identityToken = Data("\(session.spd.dsid):\(session.spd.idmsToken)".utf8).base64EncodedString()
        let anisette = try await provider.anisette()

        var headers = try anisette.twoFactorHeaders()
        if !sms {
            headers["Content-Type"] = "text/x-xml-plist"
            headers["Accept"] = "text/x-xml-plist"
        } else {
            headers["Content-Type"] = "application/json"
        }
        headers["User-Agent"] = "Xcode"
        headers["Accept-Language"] = "en-us"
        headers["X-Apple-Identity-Token"] = identityToken
        if let locale = anisette.headerValue(for: "X-Apple-Locale") {
            headers["Loc"] = locale
        }
        return headers
    }

    // MARK: - Account

    private static func buildAccount(
        email: String,
        password: String,
        spd: SPD
    ) throws -> ApplePackage.Account {
        guard let passwordToken = spd.passwordToken, !passwordToken.isEmpty else {
            throw GSAError.malformedResponse("missing password token")
        }
        let store = spd.storeFront ?? resolveStoreFront(from: [:])

        return try ApplePackage.Account(
            email: email,
            password: password,
            appleId: email,
            store: store,
            firstName: spd.firstName,
            lastName: spd.lastName,
            passwordToken: passwordToken,
            directoryServicesIdentifier: spd.dsid,
            cookie: [],
            pod: nil
        )
    }

    // MARK: - Networking

    private static func sendPlistRequest(
        url: URL,
        method: String,
        headers: [String: String],
        body: [String: Any]
    ) async throws -> [String: Any] {
        let data = try PropertyListSerialization.data(fromPropertyList: body, format: .xml, options: 0)
        let response = try await sendRawRequest(url: url, method: method, headers: headers, body: data)
        let dictionary = try parsePlist(response)
        guard let payload = dictionary["Response"] as? [String: Any] else {
            throw GSAError.malformedResponse("missing Response")
        }
        return payload
    }

    private static func parsePlist(_ data: Data) throws -> [String: Any] {
        guard let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any] else {
            throw GSAError.malformedResponse("invalid plist response")
        }
        return plist
    }

    private static func checkServiceError(_ response: [String: Any]) throws {
        let status = (response["Status"] as? [String: Any]) ?? response
        let code = integer(status["ec"]) ?? 0
        guard code != 0 else { return }
        let message = (status["em"] as? String) ?? "unknown error"
        throw GSAError.serviceError(code: code, message: message)
    }

    private static func integer(_ value: Any?) -> Int? {
        if let value = value as? Int { return value }
        if let value = value as? Int64 { return Int(value) }
        if let value = value as? NSNumber { return value.intValue }
        return nil
    }

    private static func sendRawRequest(
        url: URL,
        method: String,
        headers: [String: String],
        body: Data?,
        acceptableStatusCodes: Set<Int> = [],
        redirectCount: Int = 0,
        slashRetry: Bool = false
    ) async throws -> Data {
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.httpBody = body
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.timeoutInterval = 30
        for (key, value) in headers { request.setValue(value, forHTTPHeaderField: key) }

        let (data, response) = try await noRedirectSession.data(for: request)
        guard let http = response as? HTTPURLResponse else { return data }

        if (300 ... 399).contains(http.statusCode) {
            guard redirectCount < 3 else {
                throw GSAError.malformedResponse("too many redirects (\(http.statusCode)) for \(method) \(url.absoluteString)")
            }
            guard let location = http.value(forHTTPHeaderField: "Location"),
                  let nextURL = URL(string: location, relativeTo: url)?.absoluteURL
            else {
                throw GSAError.malformedResponse("redirect (\(http.statusCode)) without Location for \(method) \(url.absoluteString)")
            }
            let nextMethod = http.statusCode == 303 ? "GET" : method
            let nextBody = http.statusCode == 303 ? nil : body
            return try await sendRawRequest(
                url: nextURL,
                method: nextMethod,
                headers: headers,
                body: nextBody,
                acceptableStatusCodes: acceptableStatusCodes,
                redirectCount: redirectCount + 1,
                slashRetry: slashRetry
            )
        }

        if http.statusCode == 405, !slashRetry, !url.path.hasSuffix("/") {
            var components = URLComponents(url: url, resolvingAgainstBaseURL: false)
            if var path = components?.path, !path.hasSuffix("/") {
                path.append("/")
                components?.path = path
            }
            if let retryURL = components?.url {
                return try await sendRawRequest(
                    url: retryURL,
                    method: method,
                    headers: headers,
                    body: body,
                    acceptableStatusCodes: acceptableStatusCodes,
                    redirectCount: redirectCount,
                    slashRetry: true
                )
            }
        }

        if !(200 ... 299).contains(http.statusCode), !acceptableStatusCodes.contains(http.statusCode) {
            let correlation = http.value(forHTTPHeaderField: "X-Apple-Jingle-Correlation-Key")
                ?? http.value(forHTTPHeaderField: "x-apple-jingle-correlation-key")
            if http.statusCode == 403, let correlation {
                throw GSAError.legacyForbidden(correlationKey: correlation)
            }
            let snippet = data.isEmpty ? "<empty>" : (String(data: data, encoding: .utf8).map { String($0.prefix(200)) } ?? "<\(data.count) bytes>")
            throw GSAError.malformedResponse("HTTP \(http.statusCode) for \(method) \(url.absoluteString) | \(snippet)")
        }

        return data
    }

    // MARK: - Random

    private static func randomBytes(count: Int) throws -> Data {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { pointer in
            SecRandomCopyBytes(kSecRandomDefault, count, pointer.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw GSAError.malformedResponse("failed to generate random bytes")
        }
        return data
    }

    private final class NoRedirectDelegate: NSObject, URLSessionTaskDelegate {
        func urlSession(
            _: URLSession,
            task _: URLSessionTask,
            willPerformHTTPRedirection _: HTTPURLResponse,
            newRequest _: URLRequest,
            completionHandler: @escaping (URLRequest?) -> Void
        ) {
            completionHandler(nil)
        }
    }

    private static let noRedirectSession: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.urlCache = nil
        configuration.httpShouldSetCookies = false
        return URLSession(configuration: configuration, delegate: NoRedirectDelegate(), delegateQueue: nil)
    }()
}

extension Data {
    var hexLowercased: String { map { String(format: "%02x", $0) }.joined() }
}
