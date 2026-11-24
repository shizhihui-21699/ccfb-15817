// CrewAuthenticator.swift
// 机组解锁与签字授权的核心。
//
// 流程（全部离线）：
//   1. unlock(pin:) —— 检查锁定状态 → 校验 PIN（PBKDF2）→ 解开密封载荷 → 恢复 SE 密钥
//      → 签发 "会话" UnlockedCrew。
//   2. authorizeSignature(scope:) —— 每次签字前更新鲜核验：
//      * 会话未过期、未被交接；
//      * 生物识别（Face ID）通过（手套可识别）；
//      * 签发一次性 grant，绑定 (crew, session, scope, nonce, 到期时刻, 最大次数)。
//   3. 签字时 grant 被消耗一次，无法复用。
//
// "借用别人账号签字" 在这里被堵住的原因：
//   * PIN 只有本人知道；
//   * SE 密钥在本机硬件里、且每人的密钥带各自的 applicationPassword 保护；
//   * 生物识别必须在签字那一刻通过；
//   * grant 只能由当前会话签发，交接后旧会话立刻 dispose。

import Foundation
import EFBCore
import EFBCryptography

public struct SignatureGrant: Equatable, Sendable, CanonicalJSONEncodable, Codable {
    public let crewID: CrewID
    public let sessionID: SessionID
    public let scope: String
    public let nonce: String
    public let issuedAtEpoch: Double
    public let expiresAtEpoch: Double
    public let maxUses: Int
    public let presenceFactor: PresenceFactor
    public var usesRemaining: Int

    public var canonicalValue: CanonicalValue {
        .object([
            "crewID": .string(crewID.rawValue),
            "expiresAtEpoch": .int(Int(expiresAtEpoch)),
            "issuedAtEpoch": .int(Int(issuedAtEpoch)),
            "maxUses": .int(maxUses),
            "nonce": .string(nonce),
            "presenceFactor": .string(presenceFactor.rawValue),
            "scope": .string(scope),
            "sessionID": .string(sessionID.rawValue),
            "usesRemaining": .int(usesRemaining),
        ])
    }
}

public enum CredentialProblem: Equatable, Sendable {
    case revoked(CrewID)
    case expired(CrewID)
    case deviceMismatch(crew: CrewID, expected: DeviceID, actual: DeviceID)
    case certificateUntrusted(CrewID)
    case missing(CrewID)
}

public final class CrewAuthenticator: @unchecked Sendable {
    private let store: CrewCredentialStore
    private let deviceID: DeviceID
    private let policy: CrewPolicy
    private let time: TrustedTimeProviding
    private let presence: PresenceChecking
    private let keyVault: SigningKeyVault
    private let anchor: TrustAnchor
    private let issuerRecords: [IssuerRecord]
    /// 本机当前有效的撤销快照。
    /// 撤销名单可被本场预置更新，因此是 var 且带锁。
    private var revocation: RevocationSnapshot
    private let revocationMutex = NSLock()

    public init(
        store: CrewCredentialStore,
        deviceID: DeviceID,
        policy: CrewPolicy,
        time: TrustedTimeProviding,
        presence: PresenceChecking,
        keyVault: SigningKeyVault = SecureEnclaveKeyVault(),
        anchor: TrustAnchor,
        issuerRecords: [IssuerRecord],
        revocation: RevocationSnapshot
    ) {
        self.store = store
        self.deviceID = deviceID
        self.policy = policy
        self.time = time
        self.presence = presence
        self.keyVault = keyVault
        self.anchor = anchor
        self.issuerRecords = issuerRecords
        self.revocation = revocation
    }

    // MARK: 预检

    /// 在尝试解锁前先判断这台设备上该机组是否可用（吊销 / 过期 / 设备不符）。
    /// 本场预置：替换撤销名单（立即对后续解锁生效）。签名校验由调用方 BootstrapValidator 完成。
    public func updateRevocation(_ snapshot: RevocationSnapshot) {
        revocationMutex.lock()
        revocation = snapshot
        revocationMutex.unlock()
    }

    private var currentRevocation: RevocationSnapshot {
        revocationMutex.lock(); defer { revocationMutex.unlock() }
        return revocation
    }

    public func preflight(crew: CrewID) throws -> CrewCertificate {
        let now = try time.currentEpoch()
        guard let record = try store.load(crew) else {
            throw EFBError.credentialMissing(crew: crew)
        }
        let certificate = record.certificate.certificate
        // 凭据记录必须属于本次登录的 crew（防止把凭据拷到别人名下反而"借用"了角色/座位）
        guard record.crewID == crew, certificate.crewID == crew else {
            throw EFBError.credentialInvalid(reason: "凭据与机组标识不一致")
        }
        guard record.deviceID == deviceID else {
            throw EFBError.credentialDeviceMismatch(crew: crew, expected: deviceID, actual: record.deviceID)
        }
        guard currentRevocation.isRevoked(certificate: certificate) == false else {
            throw EFBError.credentialRevoked(crew: crew)
        }
        guard certificate.isTimeValid(at: now) else {
            throw EFBError.credentialExpired
        }
        guard let issuer = issuerRecords.first(where: { $0.issuerID == record.certificate.issuerID }) else {
            throw EFBError.chainUntrusted(reason: "未知签发者 \(record.certificate.issuerID)")
        }
        guard issuer.verify(with: anchor, at: now), issuer.publicKeyX963 == record.certificate.issuerPublicKeyX963 else {
            throw EFBError.chainUntrusted(reason: "签发者不受信任")
        }
        // 签发者只能为其被授权的角色签证书。
        guard issuer.permits(role: certificate.role) else {
            throw EFBError.chainUntrusted(reason: "签发者 \(issuer.issuerID) 无权签发角色 \(certificate.role.rawValue)")
        }
        // 根的用途必须包含 "crew-certificate"。
        guard anchor.purposes.contains("crew-certificate") else {
            throw EFBError.chainUntrusted(reason: "根未被授予 crew-certificate 用途")
        }
        guard record.certificate.verify(with: anchor, at: now) else {
            throw EFBError.credentialInvalid(reason: "证书签名无效")
        }
        return certificate
    }

    // MARK: 解锁

    /// 用 PIN 解锁某位机组，返回会话句柄。
    public func unlock(
        crew: CrewID,
        seat: Seat,
        pin: SecureBytes,
        audit: inout AuditLog
    ) throws -> UnlockedCrew {
        let certificate = try preflight(crew: crew)
        guard certificate.covers(seat) else {
            throw EFBError.roleNotPermitted(seat: seat, role: certificate.role)
        }

        guard let record = try store.load(crew) else {
            throw EFBError.credentialMissing(crew: crew)
        }
        let now = try time.currentEpoch()
        var payload = try openPayload(record: record, crew: crew)
        try PINAttemptTracker.checkLockout(state: payload.attemptState, nowEpoch: now)

        let matches = try PINHasher.verify(pin: pin, against: payload.pinVerifier)
        guard matches else {
            // recordFailure 会"先改状态再抛错"，所以不能让它把控制流带离持久化与审计。
            // 必须捕获它的错误、落盘、记审计，最后再抛出。
            let failure = Self.captureFailure(&payload.attemptState, policy: policy, now: now)
            try persist(payload: payload, into: record, crew: crew)
            audit.append(kind: .unlockFailed, atEpoch: now, crew: crew, seat: seat,
                         detail: "failures=\(payload.attemptState.consecutiveFailures)")
            throw failure
        }

        PINAttemptTracker.recordSuccess(state: &payload.attemptState)
        try persist(payload: payload, into: record, crew: crew)

        // 恢复签字密钥，并解开其门禁（此后整个会话复用）。
        // 解锁密钥从密封载荷里用 PIN 解出 —— 改 PIN 只需重新包裹它，密钥与证书不变。
        let signingSecret = try PINWrap.unwrap(
            payload.wrappedSigningSecret, pin: pin,
            salt: payload.wrapSalt, iterations: payload.wrapIterations
        )
        defer { signingSecret.wipe() }
        let signingKey = try keyVault.restore(blob: record.signingKeyBlob, protection: record.signingKeyProtection)
        try signingKey.unlock(withSecret: signingSecret, reason: "解锁 \(crew.rawValue) 的签字密钥")

        // 注意：必须重新读取，而不是用上面那个可能已陈旧的 record（
        // 失败路径已经写入过新的 attemptState）。用旧对象覆盖会悄悄回滚锁定计数。
        guard var latest = try store.load(crew) else {
            throw EFBError.credentialMissing(crew: crew)
        }
        latest.lastUnlockEpoch = now
        try store.save(latest)

        let sessionID = try SessionID(validating: "S-" + record.crewID.rawValue + "-" + String(UUID().uuidString.prefix(12)))
        let hardExpiry = min(now + policy.leaseMaxDurationSeconds, certificate.notAfterEpoch)
        audit.append(kind: .unlock, atEpoch: now, crew: crew, seat: seat, detail: "session=\(sessionID.rawValue)")

        return UnlockedCrew(
            crewID: crew,
            seat: seat,
            role: certificate.role,
            certificate: certificate,
            sessionID: sessionID,
            unlockedAtEpoch: now,
            hardExpiryEpoch: hardExpiry,
            signingKey: signingKey,
            presence: presence,
            policy: policy
        )
    }

    /// 空闲锁屏后重新解锁**当前**会话的签字密钥（不新开会话，也不改变 sessionID）。
    ///
    /// 与 unlock() 的区别：unlock() 会创建新的会话（同一座位已占用时会失败），
    /// 而 resume 只把已被 key.lock() 关上的门禁重新打开，保持审计与会话连续。
    public func resume(session: UnlockedCrew, pin: SecureBytes, audit: inout AuditLog) throws {
        guard !session.isDisposed else {
            throw EFBError.sessionLocked(reason: "会话已交接或登出")
        }
        let now = try time.currentEpoch()
        guard let record = try store.load(session.crewID) else {
            throw EFBError.credentialMissing(crew: session.crewID)
        }
        var payload = try openPayload(record: record, crew: session.crewID)
        try PINAttemptTracker.checkLockout(state: payload.attemptState, nowEpoch: now)
        guard try PINHasher.verify(pin: pin, against: payload.pinVerifier) else {
            let failure = Self.captureFailure(&payload.attemptState, policy: policy, now: now)
            try persist(payload: payload, into: record, crew: session.crewID)
            audit.append(kind: .unlockFailed, atEpoch: now, crew: session.crewID, seat: session.seat,
                         detail: "resume failures=\(payload.attemptState.consecutiveFailures)")
            throw failure
        }
        PINAttemptTracker.recordSuccess(state: &payload.attemptState)
        try persist(payload: payload, into: record, crew: session.crewID)

        let signingSecret = try PINWrap.unwrap(
            payload.wrappedSigningSecret, pin: pin,
            salt: payload.wrapSalt, iterations: payload.wrapIterations
        )
        defer { signingSecret.wipe() }
        try session.signingKey.unlock(withSecret: signingSecret, reason: "重新解锁 \(session.crewID.rawValue) 的签字密钥")
        audit.append(kind: .unlock, atEpoch: now, crew: session.crewID, seat: session.seat,
                     detail: "resume session=\(session.sessionID.rawValue)")
    }

    /// 记录一次 PIN 失败并返回应抛出的错误。
    /// PINAttemptTracker.recordFailure 的设计是"先修改状态再抛错"，这里把它拆开，
    /// 让调用方能先落盘、再抛出，避免失败计数丢失。
    static func captureFailure(_ state: inout PINAttemptState, policy: CrewPolicy, now: Double) -> EFBError {
        do {
            try PINAttemptTracker.recordFailure(state: &state, policy: policy, nowEpoch: now)
            return .pinIncorrect(attemptsRemaining: 0) // 理论不可达
        } catch let error as EFBError {
            return error
        } catch {
            return .internalError("PIN 失败计数异常：\(error)")
        }
    }

    // MARK: 每次签字的现场核验

    /// 为一次签字动作签发一次性 grant。
    /// - Parameter scope: 授权范围（例如 "release:CA1831:captain"），签字时校验必须一致。
    public func authorizeSignature(
        for session: UnlockedCrew,
        scope: String,
        audit: inout AuditLog
    ) async throws -> SignatureGrant {
        let now = try time.currentEpoch()
        try session.ensureActive(at: now)
        try recheckCredential(crew: session.crewID, at: now)

        if policy.presenceRequired {
            let presenceResult = try await session.presence.evaluate(reason: "\(session.crewID.rawValue) 签字放行文件")
            // 生物识别有交互时长，期间可能被交接 / 锁屏：重新校验。
            let recheckEpoch = try time.currentEpoch()
            try session.ensureActive(at: recheckEpoch)
            try recheckCredential(crew: session.crewID, at: recheckEpoch)
            switch presenceResult {
            case let .verified(factor):
                guard factor != .pinFallback || policy.presenceFallbackAllowedPerSignature > 0 else {
                    throw EFBError.presenceFailed("策略不允许回退到 PIN 代替现场核验")
                }
                audit.append(kind: .presenceCheck, atEpoch: now, crew: session.crewID, seat: session.seat,
                             detail: "factor=\(factor.rawValue)")
                let grant = SignatureGrant(
                    crewID: session.crewID,
                    sessionID: session.sessionID,
                    scope: scope,
                    nonce: UUID().uuidString,
                    issuedAtEpoch: recheckEpoch,
                    expiresAtEpoch: recheckEpoch + policy.grantLifetimeSeconds,
                    maxUses: policy.grantMaxUses,
                    presenceFactor: factor,
                    usesRemaining: policy.grantMaxUses
                )
                audit.append(kind: .grantIssued, atEpoch: now, crew: session.crewID, seat: session.seat,
                             detail: "scope=\(scope) uses=\(policy.grantMaxUses)")
                return grant
            case .cancelled:
                throw EFBError.presenceFailed("已取消")
            case let .unavailable(reason):
                throw EFBError.presenceUnavailable(reason)
            case let .failed(reason):
                throw EFBError.presenceFailed(reason)
            }
        }

        let grant = SignatureGrant(
            crewID: session.crewID,
            sessionID: session.sessionID,
            scope: scope,
            nonce: UUID().uuidString,
            issuedAtEpoch: now,
            expiresAtEpoch: now + policy.grantLifetimeSeconds,
            maxUses: policy.grantMaxUses,
            presenceFactor: .pinFallback,
            usesRemaining: policy.grantMaxUses
        )
        audit.append(kind: .grantIssued, atEpoch: now, crew: session.crewID, seat: session.seat, detail: "scope=\(scope)")
        return grant
    }

    /// 消耗一次 grant —— 由签字方在真正签名前调用。
    public func consume(_ grant: inout SignatureGrant, session: UnlockedCrew, scope: String, at epoch: Double) throws {
        guard grant.scope == scope else {
            throw EFBError.grantScopeMismatch(reason: "授权范围 \(grant.scope) ≠ \(scope)")
        }
        guard grant.sessionID == session.sessionID else {
            throw EFBError.grantScopeMismatch(reason: "授权不属于当前会话")
        }
        guard epoch <= grant.expiresAtEpoch else { throw EFBError.grantExpired }
        guard grant.usesRemaining > 0 else { throw EFBError.grantExhausted }
        grant.usesRemaining -= 1
    }

    // MARK: 内部

    private func recheckCredential(crew: CrewID, at epoch: Double) throws {
        guard let record = try store.load(crew) else { throw EFBError.credentialMissing(crew: crew) }
        guard !currentRevocation.isRevoked(certificate: record.certificate.certificate) else {
            throw EFBError.credentialRevoked(crew: crew)
        }
        guard record.certificate.certificate.isTimeValid(at: epoch) else {
            throw EFBError.credentialExpired
        }
    }

    private func openPayload(record: CrewCredentialRecord, crew: CrewID) throws -> SealedCredentialPayload {
        let sealingKey = SecureEnclaveSealingKey(blob: record.sealingKeyBlob)
        let plaintext: Data
        do {
            plaintext = try sealingKey.open(record.sealedPayload)
        } catch {
            throw EFBError.keyBindingMismatch(reason: "凭据密封件无法在本机解开")
        }
        do {
            return try JSONDecoder().decode(SealedCredentialPayload.self, from: plaintext)
        } catch {
            throw EFBError.malformedEncoding(field: "CrewCredentialPayload")
        }
    }

    private func persist(payload: SealedCredentialPayload, into record: CrewCredentialRecord, crew: CrewID) throws {
        let sealingKey = SecureEnclaveSealingKey(blob: record.sealingKeyBlob)
        let plaintext = try JSONEncoder().encode(payload)
        var updated = record
        updated.sealedPayload = try CredentialSealer.seal(plaintext, to: sealingKey.sealingPublicKeyX963)
        try store.save(updated)
    }
}
