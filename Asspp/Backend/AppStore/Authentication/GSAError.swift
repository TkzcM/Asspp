//
//  GSAError.swift
//  Asspp
//

import Foundation

enum GSAError: Error, LocalizedError, Sendable {
    case legacyForbidden(correlationKey: String?)
    case twoFactorRequired(String)
    case invalidTwoFactorCode
    case serviceError(code: Int, message: String)
    case malformedResponse(String)
    case anisetteUnavailable(String)

    var errorDescription: String? {
        switch self {
        case let .legacyForbidden(correlationKey):
            if let correlationKey, !correlationKey.isEmpty {
                return "Apple rejected the legacy sign-in endpoint (HTTP 403, correlation: \(correlationKey))."
            }
            return "Apple rejected the legacy sign-in endpoint (HTTP 403)."
        case let .twoFactorRequired(message):
            return message
        case .invalidTwoFactorCode:
            return String(localized: "Invalid verification code.")
        case let .serviceError(code, message):
            return "Apple ID authentication failed (code \(code)): \(message)"
        case let .malformedResponse(message):
            return "Apple ID authentication failed: \(message)"
        case let .anisetteUnavailable(message):
            return "Anisette unavailable: \(message)"
        }
    }
}
