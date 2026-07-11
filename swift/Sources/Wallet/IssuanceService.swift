import CborCose
import CredentialStore
import Foundation
import MDoc
import OpenID4VCI
import SdJwt
import WalletAPI

/// OpenID4VCI issuance. Owns key creation, issuance, persistence, and follow-ups.
public struct IssuanceService {
    let vci: Openid4VciClient
    let store: DefaultCredentialStore
    let storage: any StorageDriver
    let secureArea: any SecureArea
    let rng: any Rng
    let clock: any WalletClock
    let redirectUri: String

    private struct BuiltKeys { let keys: IssuanceKeys; let proofKeys: [KeyInfo]; let dpopKey: KeyInfo }

    /// Step 1 of the 2-phase flow: resolve an offer deep link / QR / raw JSON.
    public func resolveOffer(_ offerUri: String) async throws -> CredentialOffer {
        CredentialOffer(try await catchingVci { try await vci.resolveCredentialOffer(offerUri) })
    }

    /// Starts an issuance session — pre-authorized or authorization-code grant, driven as a state machine.
    public func start(_ request: IssuanceRequest) -> IssuanceSession {
        session { s in
            s.emit(.processing)
            let built = try await buildKeys(request.keySpec, batchSize: request.policy.batchSize)
            let response: CredentialResponse
            switch request.source {
            case let .fromOffer(offer): response = try await issueFromOffer(s, offer, request, built.keys)
            case let .fromIssuer(issuer): response = try await authorizationCodeFlow(s, issuer, request.configurationId, nil, built.keys)
            }
            // §9.2: the issuer may defer issuance — store the credential deferred and surface a .deferred
            // state (with the retry instant) instead of .completed, so the host knows to resume later.
            if response.isDeferred {
                let id = try await persistDeferred(response, built, request)
                s.emit(.deferred(credentialId: id, retryAfter: retryInstant(response)))
                return
            }
            let id = try await persistIssued(response, built.proofKeys.map { $0.handle }, built.dpopKey.handle, request.policy, existingId: nil)
            s.emit(.completed(IssuanceResult(issued: [id])))
        }
    }

    /// Retries a deferred credential (OpenID4VCI §9). Ends in `.completed` when the issuer is ready, or
    /// `.deferred` again (§9.2, HTTP 202) when it still needs more time.
    public func resumeDeferred(_ credentialId: CredentialId) -> IssuanceSession {
        session { s in
            s.emit(.processing)
            guard let envelope = try await store.get(credentialId) else { throw IssuanceError.credentialRequestFailed("credential not found") }
            guard case let .deferred(transactionContext, _) = envelope.lifecycle else { throw IssuanceError.credentialRequestFailed("credential is not deferred") }
            let ctx = try FollowUpContext.decode(transactionContext)
            let keys = try await rebuildKeys(ctx)
            let response = try await catchingVci { try await vci.fetchDeferredCredential(ctx.toCredentialResponse(), keys: keys) }

            // §9.2: still deferred — refresh the stored transaction_id + retryAfter and report .deferred again.
            if response.isDeferred {
                let retryAfter = retryInstant(response)
                let refreshed = ctx.withTransactionId(response.transactionId).encode()
                try await store.save(CredentialEnvelope(id: envelope.id, format: envelope.format, createdAt: envelope.createdAt,
                                                        lifecycle: .deferred(transactionContext: refreshed, retryAfter: retryAfter), metadata: envelope.metadata))
                s.emit(.deferred(credentialId: credentialId, retryAfter: retryAfter))
                return
            }

            let id = try await persistIssued(response, ctx.proofKeys, ctx.dpopKey, ctx.policy, existingId: credentialId)
            s.emit(.completed(IssuanceResult(issued: [id])))
        }
    }

    /// The §8.3 `interval` as an absolute instant, or nil when the issuer gave none.
    private func retryInstant(_ response: CredentialResponse) -> Date? {
        response.interval.map { clock.now().addingTimeInterval(TimeInterval($0)) }
    }

    /// Renews a credential via the stored refresh token (RFC 6749 §6) — rotates to fresh proof keys.
    public func reissue(_ credentialId: CredentialId) -> IssuanceSession {
        session { s in
            s.emit(.processing)
            guard let ctx = try await loadFollowUp(credentialId) else { throw IssuanceError.credentialRequestFailed("credential cannot be reissued") }
            let fresh = try await buildKeys(KeySpec(secureArea: secureArea.id), batchSize: ctx.policy.batchSize, dpopKey: ctx.dpopKey)
            let response = try await catchingVci { try await vci.reissue(ctx.toCredentialResponse(), keys: fresh.keys) }
            let id = try await persistIssued(response, fresh.proofKeys.map { $0.handle }, ctx.dpopKey, ctx.policy, existingId: credentialId)
            s.emit(.completed(IssuanceResult(issued: [id])))
        }
    }

    private func session(_ flow: @escaping (IssuanceSession) async throws -> Void) -> IssuanceSession {
        let s = IssuanceSession(flow)
        s.launch()
        return s
    }

    private func issueFromOffer(_ s: IssuanceSession, _ offer: CredentialOffer, _ request: IssuanceRequest, _ keys: IssuanceKeys) async throws -> CredentialResponse {
        if offer.raw.preAuthorizedCode != nil {
            let txCode: String?
            if let provided = request.txCode {
                txCode = provided
            } else if offer.requiresTxCode {
                txCode = await s.awaitTxCode(offer.txCode)
            } else {
                txCode = nil
            }
            return try await catchingVci { try await vci.issueWithPreAuthorizedCode(offer: offer.raw, configurationId: request.configurationId, keys: keys, txCode: txCode) }
        }
        return try await authorizationCodeFlow(s, offer.raw.credentialIssuer, request.configurationId, offer.raw.authorizationCodeIssuerState, keys)
    }

    private func authorizationCodeFlow(_ s: IssuanceSession, _ credentialIssuer: String, _ configurationId: String, _ issuerState: String?, _ keys: IssuanceKeys) async throws -> CredentialResponse {
        let prepared = try await catchingVci {
            try await vci.prepareAuthorizationCodeIssuance(credentialIssuer: credentialIssuer, configurationId: configurationId, redirectUri: redirectUri, issuerState: issuerState)
        }
        let redirect = await s.awaitAuthorization(prepared.authorizationUrl)
        guard let code = extractCode(redirect) else { throw IssuanceError.authorizationFailed(oauthError: nil, message: "no authorization code in redirect") }
        return try await catchingVci { try await vci.finishAuthorizationCodeIssuance(prepared: prepared, authorizationCode: code, keys: keys) }
    }

    private func buildKeys(_ keySpec: KeySpec, batchSize: Int, dpopKey: KeyHandle? = nil) async throws -> BuiltKeys {
        let spec = KeySpec(secureArea: secureArea.id, algorithm: keySpec.algorithm, userAuthentication: keySpec.userAuthentication,
                           hardware: keySpec.hardware, attestationChallenge: keySpec.attestationChallenge)
        var proofKeys: [KeyInfo] = []
        for _ in 0..<max(1, batchSize) { proofKeys.append(try await secureArea.createKey(spec: spec)) }
        let dpop: KeyInfo
        if let handle = dpopKey {
            dpop = KeyInfo(handle: handle, algorithm: spec.algorithm, publicKey: try await secureArea.publicKey(key: handle))
        } else {
            dpop = try await secureArea.createKey(spec: spec)
        }
        func signer(_ k: KeyInfo) -> SecureAreaJwsSigner { SecureAreaJwsSigner(area: secureArea, key: k.handle, algorithm: k.algorithm) }
        let keys = IssuanceKeys(
            proofSigner: signer(proofKeys[0]), proofPublicKey: proofKeys[0].publicKey,
            dpopSigner: signer(dpop), dpopPublicKey: dpop.publicKey,
            additionalProofKeys: proofKeys.dropFirst().map { ProofKey(signer: signer($0), publicKey: $0.publicKey) })
        return BuiltKeys(keys: keys, proofKeys: proofKeys, dpopKey: dpop)
    }

    private func rebuildKeys(_ ctx: FollowUpContext) async throws -> IssuanceKeys {
        func signer(_ h: KeyHandle) -> SecureAreaJwsSigner { SecureAreaJwsSigner(area: secureArea, key: h, algorithm: .es256) }
        var proofPubs: [EcPublicKey] = []
        for h in ctx.proofKeys { proofPubs.append(try await secureArea.publicKey(key: h)) }
        let dpopPub = try await secureArea.publicKey(key: ctx.dpopKey)
        var additional: [ProofKey] = []
        for (i, h) in ctx.proofKeys.enumerated() where i > 0 { additional.append(ProofKey(signer: signer(h), publicKey: proofPubs[i])) }
        return IssuanceKeys(proofSigner: signer(ctx.proofKeys[0]), proofPublicKey: proofPubs[0],
                            dpopSigner: signer(ctx.dpopKey), dpopPublicKey: dpopPub, additionalProofKeys: additional)
    }

    private func persistDeferred(_ response: CredentialResponse, _ built: BuiltKeys, _ request: IssuanceRequest) async throws -> CredentialId {
        let ctx = contextOf(response, built.proofKeys.map { $0.handle }, built.dpopKey.handle, request.policy, request.configurationId)
        let id = newId()
        let format: CredentialFormat = ctx.requestedFormat == "mso_mdoc" ? .msoMdoc(docType: ctx.configurationId) : .sdJwtVc(vct: ctx.configurationId)
        try await store.save(CredentialEnvelope(id: id, format: format, createdAt: clock.now(),
                                                lifecycle: .deferred(transactionContext: ctx.encode(), retryAfter: retryInstant(response)), metadata: await captureMetadata(response)))
        return id
    }

    private func persistIssued(_ response: CredentialResponse, _ proofKeys: [KeyHandle], _ dpopKey: KeyHandle, _ policy: CredentialPolicy, existingId: CredentialId?) async throws -> CredentialId {
        guard !response.credentials.isEmpty else { throw IssuanceError.credentialRequestFailed("issuer returned no credentials") }
        for credential in response.credentials { try rejectIssuerBoundKb(credential) }
        let (format, _) = try decode(response.credentials[0])
        var instances: [CredentialInstance] = []
        for (i, credential) in response.credentials.enumerated() {
            instances.append(CredentialInstance(key: proofKeys[i], payload: try decode(credential).1))
        }
        let id = existingId ?? newId()
        try await store.save(CredentialEnvelope(id: id, format: format, createdAt: clock.now(),
                                                lifecycle: .issued(policy: policy, instances: instances), metadata: await captureMetadata(response)))
        try await storage.put(collection: "followup", key: id.value, value: contextOf(response, proofKeys, dpopKey, policy, response.configurationId ?? "").encode())
        await autoNotify(response, dpopKey)
        return id
    }

    private func contextOf(_ response: CredentialResponse, _ proofKeys: [KeyHandle], _ dpopKey: KeyHandle, _ policy: CredentialPolicy, _ configurationId: String) -> FollowUpContext {
        FollowUpContext(credentialIssuer: response.credentialIssuer ?? "", configurationId: response.configurationId ?? configurationId,
                        requestedFormat: response.requestedFormat, accessToken: response.accessToken, refreshToken: response.refreshToken,
                        transactionId: response.transactionId, notificationId: response.notificationId, proofKeys: proofKeys, dpopKey: dpopKey, policy: policy)
    }

    private func loadFollowUp(_ id: CredentialId) async throws -> FollowUpContext? {
        guard let bytes = try await storage.get(collection: "followup", key: id.value) else { return nil }
        return try FollowUpContext.decode(bytes)
    }

    private func captureMetadata(_ response: CredentialResponse) async -> CredentialMetadata? {
        guard let issuer = response.credentialIssuer, let configId = response.configurationId else { return nil }
        do {
            let metadata = try await vci.loadIssuerMetadata(issuer)
            let config = metadata.credentialConfigurationsSupported[configId]
            return CredentialMetadata(issuerUrl: issuer, issuerDisplayName: metadata.issuerDisplayName, configurationId: configId,
                                      displayName: config?.displayName, logoUri: config?.logoUri, backgroundColor: config?.backgroundColor)
        } catch { return nil }
    }

    private func autoNotify(_ response: CredentialResponse, _ dpopKey: KeyHandle) async {
        guard response.notificationId != nil else { return }
        do {
            let signer = SecureAreaJwsSigner(area: secureArea, key: dpopKey, algorithm: .es256)
            let pub = try await secureArea.publicKey(key: dpopKey)
            try await vci.sendNotification(response, event: .credentialAccepted,
                                           keys: IssuanceKeys(proofSigner: signer, proofPublicKey: pub, dpopSigner: signer, dpopPublicKey: pub))
        } catch { /* best-effort */ }
    }

    private func newId() -> CredentialId { CredentialId("cred-" + Base64Url.encode(rng.nextBytes(12))) }

    /// RFC 9901 §7.2: the Holder must reject an SD-JWT the Issuer delivered already carrying a KB-JWT — the
    /// KB-JWT is the Holder's to add at presentation. Enforced here, at ingestion, before anything is stored.
    private func rejectIssuerBoundKb(_ credential: IssuedCredential) throws {
        if credential.format == "mso_mdoc" { return }
        do {
            _ = try SdJwt.parseFromIssuer(credential.credential)
        } catch let e as SdJwtError {
            throw IssuanceError.credentialRequestFailed(e.description)
        }
    }

    private func decode(_ credential: IssuedCredential) throws -> (CredentialFormat, [UInt8]) {
        if credential.format == "mso_mdoc" {
            let bytes = try Base64Url.decode(credential.credential)
            return (.msoMdoc(docType: try IssuerSigned.decode(bytes).parseMso().docType), bytes)
        }
        var vct = ""
        if case let .str(v)? = try SdJwtHolder.processedClaims(SdJwt.parse(credential.credential))["vct"] { vct = v }
        return (.sdJwtVc(vct: vct), Array(credential.credential.utf8))
    }

    /// Extracts and URL-decodes the `code` from an authorization redirect (it is re-encoded for the token request).
    private func extractCode(_ redirectUri: String) -> String? {
        guard let range = redirectUri.range(of: "code=") else { return nil }
        let raw = String(redirectUri[range.upperBound...].prefix(while: { $0 != "&" }))
        if raw.isEmpty { return nil }
        return raw.removingPercentEncoding ?? raw
    }

    private func catchingVci<T>(_ block: () async throws -> T) async throws -> T {
        do {
            return try await block()
        } catch VciError.invalidOffer(let m) {
            throw IssuanceError.invalidOffer(m)
        } catch VciError.oauth(let error, _, _) {
            throw IssuanceError.authorizationFailed(oauthError: error, message: error)
        } catch let e as VciError {
            throw IssuanceError.credentialRequestFailed(String(describing: e))
        }
    }
}
