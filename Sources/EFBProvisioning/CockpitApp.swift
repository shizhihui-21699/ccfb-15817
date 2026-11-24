// CockpitApp.swift
// 驾驶舱平板对外的统一装配层：把身份、会话、放行、归档串起来供 UI 调用。
//
// 放在 EFBProvisioning 而不是 EFBIdentity：它同时依赖 EFBIdentity 与 EFBRelease，
// 且组件全部可注入（真实 SE / Face ID / Keychain 或测试替身），因此平台无关。

import Foundation
import EFBCore
import EFBCryptography
import EFBIdentity
import EFBRelease
import EFBSession

public final class CockpitApp: @unchecked Sendable {
    public let deviceID: DeviceID
    public private(set) var policy: CrewPolicy
    private let tokenStore: ReleaseTokenStore
    private let timeProvider: TrustedTimeProviding
    private let clock: MonotonicClock
    private let presence: PresenceChecking
    private let keyVault: SigningKeyVault
    private let credentialStore: CrewCredentialStore
    private let secureStore: SecureStoring
    private let enroller: CrewEnroller
    private let archive: ReleaseArchive
    private let mutex = NSLock()
    private var audit = AuditLog()

    /// 预置状态（全部来自已校验的 BootstrapPackage）。
    private struct Provisioned: Sendable {
        let trustAnchor: TrustAnchor
        let issuers: [IssuerRecord]
        let revocation: RevocationSnapshot
        let enroller: CrewEnroller
        let sessions: SessionManager
        let authenticator: CrewAuthenticator
        let signer: ReleaseSigner
    }
    private var provisioned: Provisioned?

    /// 公司根：**编译期预置**，绝不从网络获取。
    public let pinnedAnchor: TrustAnchor

    public init(
        deviceID: DeviceID,
        pinnedAnchor: TrustAnchor,
        tokenStore: ReleaseTokenStore,
        timeProvider: TrustedTimeProviding,
        clock: MonotonicClock = SystemMonotonicClock(),
        policy: CrewPolicy = .standard,
        store: SecureStoring = KeychainSecureStore(),
        keyVault: SigningKeyVault = SecureEnclaveKeyVault(),
        presence: PresenceChecking = LocalAuthenticationGate()
    ) {
        self.deviceID = deviceID
        self.pinnedAnchor = pinnedAnchor
        self.policy = policy
        self.tokenStore = tokenStore
        self.timeProvider = timeProvider
        self.clock = clock
        self.presence = presence
        self.keyVault = keyVault
        self.secureStore = store
        self.credentialStore = CrewCredentialStore(store: store)
        self.enroller = CrewEnroller(
            store: credentialStore, deviceID: deviceID, policy: policy,
            time: timeProvider, keyVault: keyVault
        )
        self.archive = ReleaseArchive(store: store)
        // 未调用 bootstrap() 前，任何解锁都会被拒绝（无根、无签发者）。
    }

    private func requireProvisioned() throws -> Provisioned {
        mutex.lock(); defer { mutex.unlock() }
        guard let provisioned else {
            throw EFBError.chainUntrusted(reason: "尚未完成本场预置")
        }
        return provisioned
    }

    private func provisionedSnapshot() -> Provisioned? {
        mutex.lock(); defer { mutex.unlock() }
        return provisioned
    }

    // MARK: 预置阶段（装配机组凭据，只在本场做）

    /// 阶段 1：为该机组在本机生成签字密钥。公钥应提交给公司签证书。
    public func prepareCrewKey(crew: CrewID, pin: SecureBytes) throws -> PendingCredentialKey {
        try enroller.prepareKey(crew: crew, pin: pin)
    }

    /// 阶段 3：把公司签发的证书与这颗密钥一起装进本机。
    public func enrollCrew(
        crew: CrewID,
        role: CrewRole,
        seats: [Seat],
        pin: SecureBytes,
        certificate: IssuedCrewCertificate,
        revocationEpoch: Int,
        key: PendingCredentialKey
    ) throws -> CrewCredentialRecord {
        try enroller.enroll(
            crew: crew, role: role, seats: seats, pin: pin,
            certificate: certificate, revocationEpoch: revocationEpoch, key: key
        )
    }

    /// 本机已预置的机组。
    public func enrolledCrew() throws -> [CrewID] {
        try credentialStore.enrolledCrew()
    }

    // MARK: 值班

    /// 机组在座位登录（输入本人 PIN 一次 + 设备解锁）。
    public func signIn(crew: CrewID, seat: Seat, pin: SecureBytes) throws -> UnlockedCrew {
        let p = try requireProvisioned()
        var log = currentAudit()
        let session = try p.authenticator.unlock(crew: crew, seat: seat, pin: pin, audit: &log)
        _ = try p.sessions.openSession(session, at: seat, audit: &log)
        commitAudit(log)
        return session
    }

    /// 空闲锁屏后重新输入 PIN，解锁当前座位会话（不新开会话）。
    public func resume(seat: Seat, pin: SecureBytes) throws {
        let p = try requireProvisioned()
        guard let session = p.sessions.occupant(of: seat) else {
            throw EFBError.handoverIncomplete(reason: "该座位没有活跃会话")
        }
        var log = currentAudit()
        try p.authenticator.resume(session: session, pin: pin, audit: &log)
        if let epoch = try? timeProvider.currentEpoch() {
            p.sessions.recordActivity(seat: seat, at: epoch)
        }
        commitAudit(log)
    }

    /// 主动登出：旧会话的签字密钥门禁立即作废。
    public func signOut(seat: Seat) throws {
        let p = try requireProvisioned()
        var log = currentAudit()
        try p.sessions.signOut(seat: seat, audit: &log)
        commitAudit(log)
    }

    /// 新机组接管（旧机组不在场时，需要主管授权）。
    public func handOver(
        session: UnlockedCrew,
        seat: Seat,
        authorization: TakeoverAuthorization? = nil,
        acknowledgeCustodyGap: Bool = false,
        trustedTakeoverIssuerKey: Data? = nil
    ) throws -> HandoverRecord {
        let p = try requireProvisioned()
        let trustedKey = trustedTakeoverIssuerKey
            ?? p.issuers.first { $0.issuerID == authorization?.issuerID }?.publicKeyX963
        guard authorization == nil || trustedKey != nil else {
            throw EFBError.handoverIncomplete(reason: "未预置该接管授权的签发者公钥")
        }
        var log = currentAudit()
        let record = try p.sessions.openSession(
            session, at: seat,
            takeoverAuthorization: authorization,
            trustedTakeoverIssuerKey: trustedKey,
            acknowledgeCustodyGap: acknowledgeCustodyGap,
            audit: &log
        )
        commitAudit(log)
        return record
    }

    // MARK: 签字

    /// 每次签字都触发一次独立 Face ID，并消耗一次预发令牌。
    public func signRelease(
        session: UnlockedCrew,
        content: ReleaseContent,
        purpose: ReleasePurpose,
        recordID: String,
        existing: [PilotSignature]
    ) async throws -> PilotSignature {
        let p = try requireProvisioned()
        var log = currentAudit()
        let signature = try await p.signer.sign(
            session: session, content: content, purpose: purpose,
            recordID: recordID, existingSignatures: existing, audit: &log
        )
        commitAudit(log)
        return signature
    }

    public func finalizeRelease(
        recordID: String, content: ReleaseContent, purpose: ReleasePurpose, signatures: [PilotSignature]
    ) throws -> ReleaseRecord {
        let p = try requireProvisioned()
        return try p.signer.finalize(
            recordID: recordID, content: content, purpose: purpose, signatures: signatures, audit: currentAudit()
        )
    }

    // MARK: 空闲 / 结束

    /// UI 应在前台每次触摸时调用；无触摸时周期调用也应安全。
    public func reportActivity(seat: Seat) {
        guard let p = provisionedSnapshot(), let epoch = try? effectiveTime.currentEpoch() else { return }
        p.sessions.recordActivity(seat: seat, at: epoch)
    }

    /// 判定空闲锁定并返回被锁座位。
    public func lockIdleSeats() -> [Seat] {
        guard let p = provisionedSnapshot(), let epoch = try? effectiveTime.currentEpoch() else { return [] }
        var log = currentAudit()
        let locked = p.sessions.lockIdleSessions(at: epoch, audit: &log)
        commitAudit(log)
        return locked
    }

    /// 应用进入后台 / 锁屏 / 交接前调用：丢弃所有座位的签字密钥门禁。
    public func lockAllSeats() {
        guard let p = provisionedSnapshot() else { return }
        for seat in p.sessions.activeSeats() {
            p.sessions.occupant(of: seat)?.signingKey.lock()
        }
    }

    /// 审计快照（落地随包上传）。
    public var auditSnapshot: AuditLog {
        mutex.lock(); defer { mutex.unlock() }
        return audit
    }

    // MARK: 本场预置

    /// 本场联网时：校验并装入预置材料（时间锚、根、签发者、撤销名单、令牌、策略）。
    ///
    /// 这是唯一需要网络的步骤。装载后进入驾驶舱全程离线。
    /// 若仍有活跃会话，拒绝重装 —— 换锚会让在途签字的时间证明失真。
    public func bootstrap(_ package: BootstrapPackage, nowEpoch: Double) throws {
        try BootstrapValidator.validate(
            package, deviceID: deviceID, nowEpoch: nowEpoch,
            pinnedAnchor: pinnedAnchor, pinRootPublicKey: pinnedAnchor.publicKeyX963
        )
        mutex.lock()
        if let existing = provisioned, !existing.sessions.activeSeats().isEmpty {
            mutex.unlock()
            throw EFBError.internalError("仍有活跃会话，不能重装预置包；请先让所有座位登出")
        }
        mutex.unlock()

        // 时间锚：用包内锚 + 当前单调时钟构造新的时间源。
        let timeSource = try AnchoredTimeProvider(anchor: package.anchor, clock: clock)
        try tokenStore.load(package.tokens)

        let policy = package.policy
        let sessions = SessionManager(policy: policy, time: timeSource, deviceID: deviceID, store: secureStore)
        let enroller = CrewEnroller(
            store: credentialStore, deviceID: deviceID, policy: policy,
            time: timeSource, keyVault: keyVault
        )
        let authenticator = CrewAuthenticator(
            store: credentialStore, deviceID: deviceID, policy: policy, time: timeSource,
            presence: presence, keyVault: keyVault, anchor: pinnedAnchor,
            issuerRecords: package.issuers, revocation: package.revocation
        )
        let signer = ReleaseSigner(
            authenticator: authenticator, tokenStore: tokenStore,
            tokenVerifier: IssuerKeyTokenVerifier(
                trustedIssuerKeys: package.issuers.reduce(into: [:]) { $0[$1.issuerID] = $1.publicKeyX963 }
            ),
            policy: policy, time: timeSource, deviceID: deviceID,
            seatCheck: { [weak sessions] crew, seat, sessionID in
                guard let sessions else { return false }
                guard let occupant = sessions.occupant(of: seat) else { return false }
                return occupant.crewID == crew && occupant.sessionID == sessionID
            }
        )
        let snapshot = Provisioned(
            trustAnchor: pinnedAnchor,
            issuers: package.issuers,
            revocation: package.revocation,
            enroller: enroller,
            sessions: sessions,
            authenticator: authenticator,
            signer: signer
        )
        mutex.lock()
        self.policy = policy
        self.provisioned = snapshot
        self.timeProviderOverride = timeSource
        mutex.unlock()
    }

    // MARK: 落地

    /// 封存一条已完成的放行记录（离线归档，等待地面系统拉取）。
    public func archiveRelease(_ record: ReleaseRecord) throws {
        try archive.archive(record)
    }

    /// 地面系统拉取：返回尚未上传的记录。
    public func pendingRecords() throws -> [ReleaseRecord] {
        try archive.pendingUpload()
    }

    /// 地面系统确认上传成功后调用，避免重复上传导致公司侧判令牌重复消耗。
    public func markRecordUploaded(_ recordID: String) throws {
        try archive.markUploaded(recordID)
    }

    // MARK: 内部

    private var timeProviderOverride: TrustedTimeProviding?

    /// 优先用预置包带来的时间源；未预置时用注入的（便于测试与只读界面）。
    private var effectiveTime: TrustedTimeProviding { timeProviderOverride ?? timeProvider }

    private func currentAudit() -> AuditLog {
        mutex.lock(); defer { mutex.unlock() }
        return audit
    }

    private func commitAudit(_ log: AuditLog) {
        mutex.lock()
        audit = log
        mutex.unlock()
    }
}
