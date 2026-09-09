//
//  AppStoreDownload.swift
//  Asspp
//
//  Requests a download URL from the App Store. ApplePackage's own request
//  omits the `serialNumber` field that ipatool found to be required by
//  `volumeStoreDownloadProduct` (Apple otherwise answers failureType 5002), so
//  Asspp issues the request itself and falls back to the legacy redownload
//  dispatch endpoint, mirroring ipatool.
//

import ApplePackage
import Foundation

enum AssppDownload {
    enum Endpoint {
        case volumeStore
        case redownload

        var url: URL {
            switch self {
            case .volumeStore:
                let host = ApplePackage.Configuration.storeAPIHost(pod: nil)
                return URL(string: "https://\(host)/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct")!
            case .redownload:
                return URL(string: "https://downloaddispatch.itunes.apple.com/r/redownload")!
            }
        }

        var externalVersionKey: String {
            switch self {
            case .volumeStore: return "externalVersionId"
            case .redownload: return "appExtVrsId"
            }
        }
    }

    static func download(
        account: inout ApplePackage.Account,
        app: ApplePackage.Software,
        externalVersionID: String?,
        anisetteServerURL: URL
    ) async throws -> ApplePackage.DownloadOutput {
        let guid = ApplePackage.Configuration.deviceIdentifier
        let externalVersionID = externalVersionID ?? ""

        // Best effort: some storefronts accept the request without anisette
        // headers, but Apple's MZFinance endpoints increasingly require them.
        var anisetteHeaders: [String: String] = [:]
        if let anisette = try? await RemoteAnisetteProvider(serverURL: anisetteServerURL).anisette() {
            anisetteHeaders = (try? anisette.requestHeaders()) ?? [:]
        }

        var response = try await fetchProduct(
            from: .volumeStore,
            account: &account,
            app: app,
            guid: guid,
            externalVersionID: externalVersionID,
            anisetteHeaders: anisetteHeaders
        )

        if response["failureType"] as? String == "5002" {
            logger.debug("volumeStore rejected with 5002, retrying via redownload endpoint")
            response = try await fetchProduct(
                from: .redownload,
                account: &account,
                app: app,
                guid: guid,
                externalVersionID: externalVersionID,
                anisetteHeaders: anisetteHeaders
            )
        }

        if let failureType = response["failureType"] as? String {
            let customerMessage = response["customerMessage"] as? String
            if failureType.isEmpty, customerMessage == "MZFinance.BadLogin.Configurator_message" {
                throw GSAError.twoFactorRequired("""
                Apple ID authentication requires a verification code.
                Re-authenticate the account with a 2FA code, then retry.
                """)
            }
            switch failureType {
            case "2034", "2042":
                throw downloadError(String(localized: "Password token expired. Sign in to your account again."))
            case "9610":
                throw ApplePackageError.licenseRequired
            default:
                if customerMessage == "Your password has changed." {
                    throw downloadError(String(localized: "Password token expired. Sign in to your account again."))
                }
                if let customerMessage, !customerMessage.isEmpty {
                    throw downloadError(customerMessage)
                }
                throw downloadError("\(String(localized: "Download failed")) (failureType: \(failureType))")
            }
        }

        guard let items = response["songList"] as? [[String: Any]], let item = items.first else {
            throw downloadError(String(localized: "No items in response"))
        }
        guard let downloadURL = item["URL"] as? String, !downloadURL.isEmpty else {
            throw downloadError(String(localized: "Missing download URL"))
        }
        guard var metadata = item["metadata"] as? [String: Any] else {
            throw downloadError(String(localized: "Missing metadata"))
        }
        guard let version = metadata["bundleShortVersionString"] as? String,
              let bundleVersion = metadata["bundleVersion"] as? String
        else {
            throw downloadError(String(localized: "Missing required information"))
        }

        metadata["apple-id"] = account.email
        metadata["userName"] = account.email
        let iTunesMetadata = try PropertyListSerialization.data(
            fromPropertyList: metadata,
            format: .binary,
            options: 0
        )

        var sinfs: [ApplePackage.Sinf] = []
        if let sinfList = item["sinfs"] as? [[String: Any]] {
            for sinf in sinfList {
                guard let id = sinf["id"] as? Int64, let data = sinf["sinf"] as? Data else {
                    throw downloadError(String(localized: "Invalid sinf item"))
                }
                sinfs.append(ApplePackage.Sinf(id: id, sinf: data))
            }
        }
        guard !sinfs.isEmpty else {
            throw downloadError(String(localized: "No sinf found in response"))
        }

        return ApplePackage.DownloadOutput(
            downloadURL: downloadURL,
            sinfs: sinfs,
            bundleShortVersionString: version,
            bundleVersion: bundleVersion,
            iTunesMetadata: iTunesMetadata
        )
    }

    private static func fetchProduct(
        from endpoint: Endpoint,
        account: inout ApplePackage.Account,
        app: ApplePackage.Software,
        guid: String,
        externalVersionID: String,
        anisetteHeaders: [String: String]
    ) async throws -> [String: Any] {
        var payload: [String: Any] = [
            "creditDisplay": "",
            "guid": guid,
            "salableAdamId": app.id,
            // Required by volumeStoreDownloadProduct; without it Apple answers
            // failureType 5002.
            "serialNumber": "0",
        ]
        if !externalVersionID.isEmpty {
            payload[endpoint.externalVersionKey] = externalVersionID
        }

        var components = URLComponents(url: endpoint.url, resolvingAgainstBaseURL: false)!
        components.queryItems = [URLQueryItem(name: "guid", value: guid)]

        let body = try PropertyListSerialization.data(
            fromPropertyList: payload,
            format: .xml,
            options: 0
        )

        var currentURL = components.url!
        var redirectCount = 0
        var data = Data()
        var statusCode = 0
        while true {
            var request = URLRequest(url: currentURL)
            request.httpMethod = "POST"
            request.httpBody = body
            request.cachePolicy = .reloadIgnoringLocalCacheData
            request.timeoutInterval = 30
            request.setValue("application/x-apple-plist", forHTTPHeaderField: "Content-Type")
            request.setValue(ApplePackage.Configuration.userAgent, forHTTPHeaderField: "User-Agent")
            request.setValue(account.directoryServicesIdentifier, forHTTPHeaderField: "iCloud-DSID")
            request.setValue(account.directoryServicesIdentifier, forHTTPHeaderField: "X-Dsid")
            request.setValue("\(account.store)-1", forHTTPHeaderField: "X-Apple-Store-Front")
            request.setValue(account.passwordToken, forHTTPHeaderField: "X-Token")
            for (name, value) in anisetteHeaders where request.value(forHTTPHeaderField: name) == nil {
                request.setValue(value, forHTTPHeaderField: name)
            }
            for (name, value) in account.cookie.buildCookieHeader(currentURL) {
                request.setValue(value, forHTTPHeaderField: name)
            }

            let (responseData, response) = try await noRedirectSession.data(for: request)
            guard let http = response as? HTTPURLResponse else {
                throw downloadError(String(localized: "Invalid response"))
            }
            statusCode = http.statusCode
            data = responseData

            // Apple dispatches the request to a storefront pod with a 302 and
            // expects the same POST body to be replayed at the new host.
            if (300 ... 399).contains(http.statusCode) {
                redirectCount += 1
                guard redirectCount <= 3,
                      let location = http.value(forHTTPHeaderField: "Location"),
                      let nextURL = URL(string: location, relativeTo: currentURL)?.absoluteURL
                else {
                    throw downloadError(String(localized: "Invalid response"))
                }
                currentURL = nextURL
                continue
            }
            break
        }

        guard statusCode == 200 else {
            throw downloadError("\(String(localized: "Request failed")) (HTTP \(statusCode))")
        }

        guard let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any] else {
            throw downloadError(String(localized: "Invalid response"))
        }
        return plist
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

    private static func downloadError(_ message: String) -> NSError {
        NSError(domain: "Asspp.AppStoreDownload", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
