//
//  SigningErrorPresenter.swift
//  JPKILocalSignerApp
//
//  Maps library-level errors to clear Japanese guidance (design.md FR-12).
//  NFC user-cancellation is handled by the caller (silently returns) and is
//  not expected to reach this presenter, but a message is still provided
//  defensively.

import Foundation
import JPKILocalSigner

enum SigningErrorPresenter {
    static func message(for error: Error) -> String {
        if let nfcError = error as? NFCSessionError {
            return message(forNFCError: nfcError)
        }
        #if os(macOS)
        if let smartCardError = error as? SmartCardSessionError {
            return message(forSmartCardError: smartCardError)
        }
        #endif
        if let signingServiceError = error as? JPKICardSigningServiceError {
            return message(forCardSigningError: signingServiceError)
        }
        if let signerError = error as? JPKINFCPDFSignerError {
            return message(forSignerError: signerError)
        }
        return String(localized: "署名に失敗しました。もう一度お試しください。")
    }

    private static func message(forNFCError error: NFCSessionError) -> String {
        switch error {
        case .userCanceled:
            return String(localized: "読み取りをキャンセルしました。")
        case .readingUnavailable, .unsupportedPlatform:
            return String(localized: "この端末は NFC 読み取りに対応していません。")
        case .sessionInvalidated:
            return String(localized: "カードとの通信が中断されました。もう一度かざしてください。")
        case .tagConnectionFailed:
            return String(localized: "カードに接続できませんでした。位置を調整してもう一度かざしてください。")
        case .unsupportedTag:
            return String(localized: "カードを認識できませんでした。マイナンバーカードを iPhone にかざしてください。")
        case .cardCommunicationFailed:
            return String(localized: "カードとの通信に失敗しました。もう一度かざしてください。")
        }
    }

    private static func message(forCardSigningError error: JPKICardSigningServiceError) -> String {
        switch error {
        case .invalidPINFormat:
            return String(localized: "署名用パスワードは英数字6〜16桁で入力してください。")
        case .pinVerificationFailed(let status):
            switch status {
            case .pinVerificationFailed(let retries):
                if retries <= 0 {
                    return String(localized: "暗証番号がロックされました。市区町村の窓口で初期化してください。")
                }
                return String(localized: "暗証番号が違います（残り\(retries)回）。5回連続で間違えるとロックされ、市区町村窓口での初期化が必要になります。")
            case .authenticationMethodBlocked:
                return String(localized: "暗証番号がロックされています。市区町村の窓口で初期化してください。")
            default:
                return String(localized: "暗証番号を確認できませんでした。もう一度お試しください。")
            }
        case .unexpectedRetryQueryResponse:
            return String(localized: "カードの状態を確認できませんでした。もう一度お試しください。")
        }
    }

    #if os(macOS)
    private static func message(forSmartCardError error: SmartCardSessionError) -> String {
        switch error {
        case .smartCardServicesUnavailable:
            return String(localized: "スマートカードサービスを利用できません。アプリのスマートカード権限を確認してください。")
        case .noCardPresent:
            return String(localized: "カードリーダーにカードが見つかりません。カードを挿入してください。")
        case .cardUnavailable:
            return String(localized: "カードにアクセスできませんでした。カードを挿し直してください。")
        case .sessionFailed:
            return String(localized: "カードとの通信に失敗しました。もう一度お試しください。")
        }
    }
    #endif

    private static func message(forSignerError error: JPKINFCPDFSignerError) -> String {
        switch error {
        case .certificateOutsideValidity:
            return String(localized: "署名用電子証明書の有効期間が切れています。マイナンバーカードの更新が必要です。")
        case .pinLocked:
            return String(localized: "暗証番号がロックされています。市区町村の窓口で初期化してください。")
        case .pinLockImminent:
            // Normally intercepted by SigningFlowModel and turned into a
            // confirmation dialog; provided defensively.
            return String(localized: "暗証番号の残り試行回数が1回のため中断しました。暗証番号をよく確認してからやり直してください。")
        }
    }
}
