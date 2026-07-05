import CborCose
import CredentialStore
import Foundation
import MDoc
import OpenID4VP
import SdJwt
import TransactionLog
import Trust
import WalletAPI

/// OpenID4VP remote presentation. Bridges the store to the VP engine + records audit.
public struct PresentationService {
    let vp: Openid4VpClient
    let store: DefaultCredentialStore
    let txlog: TransactionLog
    let secureAreas: [any SecureArea]

    /// Remote (URL/QR) presentation: resolve → match stored credentials → consent → direct_post submit.
    public func start(_ requestUri: String) -> PresentationSession {
        runSession(
            resolve: { try await catchingVp { try await vp.resolveRequest(requestUri) } },
            submit: { resolved, matches, selection, held in
                let result = try await catchingVp {
                    try await vp.respond(request: resolved, matches: matches, selection: toVpSelection(selection), held: held)
                }
                return .completed(redirectUri: result.redirectUri, dcApiResponse: nil)
            })
    }

    /// Digital Credentials API presentation (browser-mediated). The platform hands over the `requestObject`
    /// and the caller `origin`; no HTTP is performed — the response object is returned in
    /// `PresentationState.completed(dcApiResponse:)` for the app to pass back to the platform.
    public func startDcApi(_ requestObject: String, origin: String) -> PresentationSession {
        runSession(
            resolve: { try await catchingVp { try await vp.resolveDcApiRequest(requestObject, origin: origin) } },
            submit: { resolved, matches, selection, held in
                let response = try await catchingVp {
                    try await vp.respondDcApi(request: resolved, matches: matches, selection: toVpSelection(selection), held: held)
                }
                return .completed(redirectUri: nil, dcApiResponse: response.serialize())
            })
    }

    private func runSession(
        resolve: @escaping () async throws -> ResolvedRequest,
        submit: @escaping (ResolvedRequest, DcqlMatchResult, PresentationSelection, [any PresentableCredential]) async throws -> PresentationState
    ) -> PresentationSession {
        let session = PresentationSession { s in
            s.emit(.resolvingRequest)
            let resolved = try await resolve()

            let envelopes = try await store.list().filter { if case .issued = $0.lifecycle { return true }; return false }
            var held: [any PresentableCredential] = []
            for envelope in envelopes {
                if let p = presentableFor(envelope, firstInstance(envelope)) { held.append(p) }
            }
            let matches = vp.match(resolved, held: held)
            let request = buildRequest(resolved, matches)

            switch await s.awaitDecision(request) {
            case .none:
                try await recordDeclined(resolved)
                s.emit(.declined)
            case let .some(selection):
                if selection.chosen.isEmpty { throw PresentationError.selectionIncomplete("no credential selected") }
                s.emit(.submitting)
                let chosenHeld = try await buildChosenHeld(envelopes, selection)
                let terminal = try await submit(resolved, matches, selection, chosenHeld)
                try await recordSuccess(resolved, selection, matches)
                s.emit(terminal)
            }
        }
        session.launch()
        return session
    }

    private func buildRequest(_ resolved: ResolvedRequest, _ matches: DcqlMatchResult) -> PresentationRequest {
        let required = matches.requiredQueryIds
        let queries = matches.candidatesByQuery.map { queryId, candidates in
            QueryPresentation(
                queryId: queryId, required: required.contains(queryId),
                candidates: candidates.map { PresentationCandidate(credentialId: CredentialId($0.credential.credentialId), disclosedPaths: $0.disclosedPaths) })
        }
        let v = resolved.verifier
        return PresentationRequest(
            verifier: VerifierInfo(clientId: v.clientId, clientIdScheme: v.clientIdScheme, commonName: v.commonName, trusted: v.trusted),
            queries: queries, transactionData: resolved.transactionData, satisfiable: matches.isSatisfiable(),
            resolved: resolved, matches: matches)
    }

    /// Consumes one instance per chosen credential (usage counting) and builds a signer-backed presentable.
    private func buildChosenHeld(_ envelopes: [CredentialEnvelope], _ selection: PresentationSelection) async throws -> [any PresentableCredential] {
        var byId: [String: CredentialEnvelope] = [:]
        for envelope in envelopes { byId[envelope.id.value] = envelope }
        var result: [any PresentableCredential] = []
        for idValue in Set(selection.chosen.values.map { $0.value }) {
            guard let envelope = byId[idValue] else { continue }
            guard let consumed = try await store.consumeInstance(CredentialId(idValue)) else { continue }
            if let p = presentableFor(envelope, consumed.instance) { result.append(p) }
        }
        return result
    }

    private func presentableFor(_ envelope: CredentialEnvelope, _ instance: CredentialInstance?) -> (any PresentableCredential)? {
        guard let instance else { return nil }
        guard let area = secureAreas.first(where: { $0.id == instance.key.secureArea }) else { return nil }
        do {
            switch envelope.format {
            case .sdJwtVc:
                return try HeldSdJwtVc(
                    credentialId: envelope.id.value,
                    sdJwt: try SdJwt.parse(String(decoding: instance.payload, as: UTF8.self)),
                    holderSigner: SecureAreaJwsSigner(area: area, key: instance.key, algorithm: .es256))
            case .msoMdoc:
                return try HeldMdoc(
                    credentialId: envelope.id.value,
                    issuerSigned: try IssuerSigned.decode(instance.payload),
                    deviceSigner: SecureAreaCoseSigner(area: area, key: instance.key, algorithm: .es256))
            }
        } catch {
            return nil
        }
    }

    private func toVpSelection(_ selection: PresentationSelection) -> OpenID4VP.PresentationSelection {
        var chosen: [String: String] = [:]
        for (queryId, credentialId) in selection.chosen { chosen[queryId] = credentialId.value }
        return OpenID4VP.PresentationSelection(chosen: chosen)
    }

    private func firstInstance(_ envelope: CredentialEnvelope) -> CredentialInstance? {
        if case let .issued(_, instances) = envelope.lifecycle { return instances.first }
        return nil
    }

    private func recordSuccess(_ resolved: ResolvedRequest, _ selection: PresentationSelection, _ matches: DcqlMatchResult) async throws {
        await txlog.recordPresentation(relyingParty: relyingPartyOf(resolved), documents: loggedDocuments(selection, matches), status: .success)
    }

    private func recordDeclined(_ resolved: ResolvedRequest) async throws {
        await txlog.recordPresentation(relyingParty: relyingPartyOf(resolved), documents: [], status: .incomplete)
    }

    private func relyingPartyOf(_ resolved: ResolvedRequest) -> RelyingParty {
        RelyingParty(id: resolved.verifier.clientId, name: resolved.verifier.commonName,
                     trusted: resolved.verifier.trusted, certificateChainDer: resolved.verifier.certificateChainDer ?? [])
    }

    private func loggedDocuments(_ selection: PresentationSelection, _ matches: DcqlMatchResult) -> [LoggedDocument] {
        selection.chosen.compactMap { queryId, credentialId in
            guard let candidate = matches.candidatesByQuery[queryId]?.first(where: { $0.credential.credentialId == credentialId.value }) else { return nil }
            return LoggedDocument(
                format: candidate.credential.format,
                type: candidate.credential.vct ?? candidate.credential.docType,
                queryId: queryId,
                claims: candidate.disclosedPaths.map { LoggedClaim(path: $0) })
        }
    }

    private func catchingVp<T>(_ block: () async throws -> T) async throws -> T {
        do {
            return try await block()
        } catch let e as TrustError {
            throw PresentationError.verifierNotTrusted(e.description)
        } catch VpError.invalidRequest(let m) {
            throw PresentationError.invalidRequest(m)
        } catch VpError.verifierNotTrusted(let m) {
            throw PresentationError.verifierNotTrusted(m)
        } catch VpError.queryNotSatisfiable(let missing) {
            throw PresentationError.queryNotSatisfiable("\(missing)")
        } catch VpError.selectionIncomplete(let m) {
            throw PresentationError.selectionIncomplete(m)
        } catch VpError.responseFailed(let m) {
            throw PresentationError.responseRejected(m)
        } catch VpError.unsupported(let m) {
            throw PresentationError.invalidRequest(m)
        }
    }
}
