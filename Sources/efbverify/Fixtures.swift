// Fixtures.swift
// 端到端测试环境：公司根、签发者、机组证书、令牌、设备侧凭据。
//
// 这里使用 SoftwareKeyVault 来模拟签字密钥（本机 headless 环境无法触发
// applicationPassword 的系统 UI），但密封密钥与 Secure Enclave 相关路径仍用真实实现，
// 并且由独立套件在真实 SE 上验证签名与不可导出性。

import Foundation
import EFBCore
import EFBCryptography
import EFBIdentity
import EFBRelease
import EFBSession
import EFBCompany
import EFBProvisioning

/// 在核验过程中执行副作用的门禁：用于验证"核验期间被交接"的竞态。
public actor InterleavingPresenceGate {
    private var sideEffect: @Sendable () -> Void
    public init(sideEffect: @escaping @Sendable () -> Void = {}) {
        self.sideEffect = sideEffect
    }

    /// 在会话创建后再挂上副作用（例如 dispose 该会话本身）。
    public func setSideEffect(_ effect: @escaping @Sendable () -> Void) {
        sideEffect = effect
    }

    func runSideEffect() {
        sideEffect()
    }
}

extension InterleavingPresenceGate: PresenceChecking {
    public nonisolated func availability() -> Bool { true }

    public func evaluate(reason: String) async throws -> PresenceResult {
        runSideEffect()
        return .verified(factor: .biometric)
    }
}

/// 一台"平板"的完整状态。
public final class TestDevice: @unchecked Sendable {
    public let deviceID: DeviceID
    public let store: InMemorySecureStore
    public let credentialStore: CrewCredentialStore
    public let keyVault: SoftwareKeyVault
    public let clock: ManualClock
    public let time: AnchoredTimeProvider
    public let presence: ScriptedPresenceGate
    public let presenceOverride: PresenceChecking?
    public let policy: CrewPolicy

    public init(
        deviceID: String,
        nowEpoch: Double = 1_700_000_000,
        policy: CrewPolicy = .standard,
        presence: ScriptedPresenceGate = ScriptedPresenceGate(),
        presenceOverride: PresenceChecking? = nil
    ) throws {
        self.deviceID = try DeviceID(validating: deviceID)
        self.store = InMemorySecureStore()
        self.credentialStore = CrewCredentialStore(store: store)
        self.keyVault = SoftwareKeyVault()
        self.clock = ManualClock(uptimeSeconds: 100)
        self.policy = policy
        self.presence = presence
        self.presenceOverride = presenceOverride
        let anchor = TimeAnchor(
            authoritativeEpoch: nowEpoch,
            monotonicAtAnchor: 100,
            issuedAtEpoch: nowEpoch,
            validitySeconds: 72 * 3600,
            driftToleranceSeconds: 60
        , bootIdentity: 1_700_000_000)
        self.time = try AnchoredTimeProvider(anchor: anchor, clock: clock)
    }

    public func advance(by seconds: Double) {
        clock.advance(by: seconds)
    }

    public func enroller() -> CrewEnroller {
        CrewEnroller(store: credentialStore, deviceID: deviceID, policy: policy, time: time, keyVault: keyVault)
    }

    public func authenticator(
        anchor: TrustAnchor,
        issuers: [IssuerRecord],
        revocation: RevocationSnapshot
    ) -> CrewAuthenticator {
        CrewAuthenticator(
            store: credentialStore,
            deviceID: deviceID,
            policy: policy,
            time: time,
            presence: presenceOverride ?? presence,
            keyVault: keyVault,
            anchor: anchor,
            issuerRecords: issuers,
            revocation: revocation
        )
    }
}

/// 公司侧（签发 + 审计）。
public final class TestCompany {
    public let authority: SigningAuthority
    public var issuerRecord: IssuerRecord
    public var issuerKey: SoftwareSigningKey
    public let issuerID = "OPS-CREW-CA"
    public let now: () -> Double
    public private(set) var issuedCertificates: [CertificateID: IssuedCertificateRecord] = [:]
    public private(set) var tokenLedger: [TokenSerial: IssuedTokenLedgerEntry] = [:]
    public private(set) var consumed: Set<TokenSerial> = []
    public private(set) var revocation: RevocationSnapshot

    public init(nowEpoch: Double = 1_700_000_000) throws {
        let box = EpochBox(nowEpoch)
        self.now = { box.value }
        self.authority = try SigningAuthority(anchorID: "AIRLINE-ROOT-2026", currentEpochProvider: { box.value })
        let (issuer, key) = try authority.delegateIssuer(
            issuerID: issuerID,
            allowedRoles: [.captain, .firstOfficer, .reliefPilot, .instructor],
            validitySeconds: 5 * 365 * 86400
        )
        self.issuerRecord = issuer
        self.issuerKey = key
        self.revocation = try authority.issueRevocationSnapshot(
            epoch: 0, revokedCertificates: [], revokedCrew: [],
            issuerID: issuerID, issuerKey: key
        )
    }

    public var anchor: TrustAnchor { authority.anchor }
    public var policyDigest: SHA256Digest { CrewPolicy.standard.canonicalSHA256 }

    /// 为某机组签发证书（公钥来自设备上的密钥）。
    public func issueCertificate(
        crew: CrewID, seat: Seat, role: CrewRole, device: DeviceID, publicKey: Data
    ) throws -> IssuedCrewCertificate {
        let certificate = try authority.issueCrewCertificate(
            crew: crew,
            device: device,
            signingPublicKeyX963: publicKey,
            role: role,
            seats: [seat, seat.counterpart],
            policyDigest: policyDigest,
            revocationEpoch: revocation.epoch,
            validitySeconds: 20 * 365 * 86400,
            issuerID: issuerID,
            issuerKey: issuerKey
        )
        issuedCertificates[certificate.certificate.certificateID] = IssuedCertificateRecord(
            certificate: certificate.certificate,
            issuerID: issuerID,
            issuerPublicKeyX963: issuerKey.publicKeyX963
        )
        return certificate
    }

    public func issueTokens(
        flight: FlightID,
        assignments: [(CrewID, Seat, DeviceID)],
        purpose: ReleasePurpose = .departure,
        from: Double? = nil,
        until: Double? = nil
    ) throws -> [ReleaseToken] {
        let tokens = try authority.issueReleaseTokens(
            flight: flight,
            crewAssignments: assignments.map { (crew: $0.0, seat: $0.1, device: $0.2) },
            purpose: purpose,
            fromEpoch: from ?? now() - 3600,
            untilEpoch: until ?? now() + 24 * 3600,
            issuerID: issuerID,
            issuerKey: issuerKey
        )
        for token in tokens {
            tokenLedger[token.serial] = IssuedTokenLedgerEntry(
                serial: token.serial, flightID: token.flightID, crewID: token.crewID,
                seat: token.seat, deviceID: token.deviceID, purpose: token.purpose,
                issuedAtEpoch: now()
            )
        }
        return tokens
    }

    public func auditContext(consumedTokens: Set<TokenSerial> = []) -> ReleaseAuditContext {
        ReleaseAuditContext(
            anchor: anchor,
            issuers: [issuerRecord],
            issuedCertificates: issuedCertificates,
            tokenLedger: tokenLedger,
            consumedTokens: consumedTokens,
            policy: .standard
        )
    }
}

final class EpochBox: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: Double
    init(_ value: Double) { stored = value }
    var value: Double {
        lock.lock(); defer { lock.unlock() }
        return stored
    }
    func advance(by seconds: Double) {
        lock.lock(); defer { lock.unlock() }
        stored += seconds
    }
}

// MARK: - 便捷构造

public enum Fixtures {
    public static func crew(_ raw: String) throws -> CrewID { try CrewID(validating: raw) }
    public static func flight(_ raw: String) throws -> FlightID { try FlightID(validating: raw) }
    public static func pin(_ digits: String) -> SecureBytes { SecureBytes(Array(digits.utf8)) }

    /// 完整的机组预置：先在设备上生成密钥，再让公司为这颗公钥签证书。
    public static func enroll(
        crew: CrewID,
        seat: Seat,
        role: CrewRole,
        pinDigits: String,
        device: TestDevice,
        company: TestCompany
    ) throws -> CrewCredentialRecord {
        // 1) 设备先造出不可导出的密钥（模拟"机组在 MDM 引导下录入"）
        let pending = try device.enroller().prepareKey(crew: crew, pin: pin(pinDigits))
        // 2) 公司只为这颗公钥签证书
        let certificate = try company.issueCertificate(
            crew: crew, seat: seat, role: role, device: device.deviceID,
            publicKey: pending.publicKeyX963
        )
        // 3) 设备落地
        return try device.enroller().enroll(
            crew: crew,
            role: role,
            seats: [seat],
            pin: pin(pinDigits),
            certificate: certificate,
            revocationEpoch: company.revocation.epoch,
            key: pending
        )
    }
}
