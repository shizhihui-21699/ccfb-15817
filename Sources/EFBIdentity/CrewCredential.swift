// CrewCredential.swift
// 一台平板上的 "可用的机组成员身份"：证书 + SE 密钥句柄 + PIN 校验器 + 锁定状态。
// 全部落盘内容都是密封件（SealedBox），密钥材料由本机 Secure Enclave 保护。

import Foundation
import EFBCore
import EFBCryptography

/// 落盘的凭据记录。除 sealedPayload 之外都可由公司重新下发。
public struct CrewCredentialRecord: Equatable, Sendable, Codable {
    public var crewID: CrewID
    public var deviceID: DeviceID
    public var certificate: IssuedCrewCertificate
    /// 证书的撤销纪元（快照版本）。
    public var revocationEpoch: Int
    /// SE 签名密钥的 dataRepresentation（本身由 SE 系统封装，仍需配 SE 才能用）。
    public var signingKeyBlob: Data
    public var signingKeyProtection: KeyProtection
    /// SE 密封密钥 blob（用于解开下面这个 payload）。
    public var sealingKeyBlob: Data
    /// 密封的敏感载荷：PIN 校验器 + 历史 PIN 校验器 + 失败计数。
    public var sealedPayload: SealedBox
    /// 最近一次成功核验的时间（审计）。
    public var lastUnlockEpoch: Double?

    public init(
        crewID: CrewID,
        deviceID: DeviceID,
        certificate: IssuedCrewCertificate,
        revocationEpoch: Int,
        signingKeyBlob: Data,
        signingKeyProtection: KeyProtection,
        sealingKeyBlob: Data,
        sealedPayload: SealedBox,
        lastUnlockEpoch: Double? = nil
    ) {
        self.crewID = crewID
        self.deviceID = deviceID
        self.certificate = certificate
        self.revocationEpoch = revocationEpoch
        self.signingKeyBlob = signingKeyBlob
        self.signingKeyProtection = signingKeyProtection
        self.sealingKeyBlob = sealingKeyBlob
        self.sealedPayload = sealedPayload
        self.lastUnlockEpoch = lastUnlockEpoch
    }
}

/// 密封载荷：只有本机 SE 能解开。
///
/// 里面除了 PIN 校验器，还带着"解锁密钥"（signingKeySecret）：
/// 随机的 32 字节，用来解开硬件签字密钥。它本身用 PIN 派生的密钥包裹，
/// 因此：知道 PIN → 解出解锁密钥 → 解开硬件密钥。
/// 改 PIN 时只需换一层包裹，证书与密钥不必更换。
public struct SealedCredentialPayload: Equatable, Sendable, Codable {
    public var pinVerifier: PINVerifier
    /// 历史 PIN 校验器（只存派生值，用于禁止复用）。
    public var pinHistory: [PINVerifier]
    public var attemptState: PINAttemptState
    public var createdAtEpoch: Double
    /// 用 PIN 派生密钥包裹的解锁密钥（AES-GCM 组合表示）。
    public var wrappedSigningSecret: Data
    /// 包裹所用的 KDF 盐与迭代次数。
    public var wrapSalt: Data
    public var wrapIterations: Int

    public init(
        pinVerifier: PINVerifier,
        pinHistory: [PINVerifier],
        attemptState: PINAttemptState,
        createdAtEpoch: Double,
        wrappedSigningSecret: Data,
        wrapSalt: Data,
        wrapIterations: Int
    ) {
        self.pinVerifier = pinVerifier
        self.pinHistory = pinHistory
        self.attemptState = attemptState
        self.createdAtEpoch = createdAtEpoch
        self.wrappedSigningSecret = wrappedSigningSecret
        self.wrapSalt = wrapSalt
        self.wrapIterations = wrapIterations
    }
}

/// 解锁后交给上层的一次性句柄。交接 / 锁屏时显式 dispose。
public final class UnlockedCrew: @unchecked Sendable {
    public let crewID: CrewID
    public let seat: Seat
    public let role: CrewRole
    public let certificate: CrewCertificate
    /// 唯一的会话标识（与审计、授权绑定）。
    public let sessionID: SessionID
    public let unlockedAtEpoch: Double
    /// 租约的硬上限（超过必须重新核验）。
    public let hardExpiryEpoch: Double

    public let signingKey: SigningKeyHandle
    let presence: PresenceChecking
    public let policy: CrewPolicy
    private let lock = NSLock()
    private var disposed = false

    init(
        crewID: CrewID,
        seat: Seat,
        role: CrewRole,
        certificate: CrewCertificate,
        sessionID: SessionID,
        unlockedAtEpoch: Double,
        hardExpiryEpoch: Double,
        signingKey: SigningKeyHandle,
        presence: PresenceChecking,
        policy: CrewPolicy
    ) {
        self.crewID = crewID
        self.seat = seat
        self.role = role
        self.certificate = certificate
        self.sessionID = sessionID
        self.unlockedAtEpoch = unlockedAtEpoch
        self.hardExpiryEpoch = hardExpiryEpoch
        self.signingKey = signingKey
        self.presence = presence
        self.policy = policy
    }

    public var isDisposed: Bool {
        lock.lock(); defer { lock.unlock() }
        return disposed
    }

    /// 交接 / 锁屏 / 登出：立即废掉 PIN 门禁并标记句柄不可再用。
    /// 任何持有的 grant 都会因 session 标记而失败。
    public func dispose() {
        lock.lock()
        guard !disposed else { lock.unlock(); return }
        disposed = true
        lock.unlock()
        signingKey.lock()
    }

    public func ensureActive(at epoch: Double) throws {
        lock.lock()
        let gone = disposed
        lock.unlock()
        if gone { throw EFBError.sessionLocked(reason: "会话已交接或登出") }
        if epoch > hardExpiryEpoch { throw EFBError.sessionStale(reason: "会话超过最长租约") }
    }
}
