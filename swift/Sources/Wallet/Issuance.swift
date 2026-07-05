import Foundation
import OpenID4VCI
import WalletAPI

/// A resolved credential offer (OpenID4VCI §4) — the first step of the 2-phase issuance flow.
public struct CredentialOffer {
    let raw: OpenID4VCI.CredentialOffer
    init(_ raw: OpenID4VCI.CredentialOffer) { self.raw = raw }

    public var credentialIssuer: String { raw.credentialIssuer }
    public var credentialConfigurationIds: [String] { raw.credentialConfigurationIds }
    public var requiresTxCode: Bool { raw.txCode != nil }
}

/// What to issue: from an offer or wallet-initiated, plus key policy and (if pre-known) the tx_code.
public struct IssuanceRequest {
    enum Source {
        case fromOffer(CredentialOffer)
        case fromIssuer(String)
    }

    let source: Source
    let configurationId: String
    let txCode: String?
    let keySpec: KeySpec
    let policy: CredentialPolicy

    /// 2-phase flow: issue an offered credential (pre-authorized or authorization-code grant).
    public static func fromOffer(_ offer: CredentialOffer, configurationId: String, txCode: String? = nil,
                                 keySpec: KeySpec = KeySpec(), policy: CredentialPolicy = CredentialPolicy()) -> IssuanceRequest {
        IssuanceRequest(source: .fromOffer(offer), configurationId: configurationId, txCode: txCode, keySpec: keySpec, policy: policy)
    }

    /// Wallet-initiated issuance from an issuer (authorization-code grant, browser step required).
    public static func fromIssuer(_ credentialIssuer: String, configurationId: String,
                                  keySpec: KeySpec = KeySpec(), policy: CredentialPolicy = CredentialPolicy()) -> IssuanceRequest {
        IssuanceRequest(source: .fromIssuer(credentialIssuer), configurationId: configurationId, txCode: nil, keySpec: keySpec, policy: policy)
    }
}

/// Terminal issuance outcome (credentials stored; ids for follow-up).
public struct IssuanceResult { public let issued: [CredentialId] }

/// Issuance session state.
public enum IssuanceState {
    case preparing
    case authorizationRequired(String)
    case txCodeRequired
    case processing
    case completed(IssuanceResult)
    case failed(IssuanceError)

    public var isTerminal: Bool {
        switch self {
        case .completed, .failed: return true
        default: return false
        }
    }
}
