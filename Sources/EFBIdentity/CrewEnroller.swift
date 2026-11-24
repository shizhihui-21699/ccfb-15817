// CrewEnroller.swift
// 设备侧预置：把公司签发材料装到平板上。
//
// 时机：在本场 / 机务准备阶段联网时完成，或由 MDM 下发。飞行中完全不需要联网。
//
// 预置必须是两阶段的，顺序不能颠倒：
//   1) 设备生成一颗**不可导出**的签字密钥，把公钥报给公司（此时还不签字）；
//   2) 公司按这颗公钥为机组签发证书，MDM 把证书下发回设备；
//   3) 设备把证书与**同一颗**密钥一起落盘。
// 若允许"公司先发证书、设备再随便生成一把密钥"，证书就与设备密钥脱钩，
// 谁都可能把别人的证书装进自己的设备 —— 这正是本方案要堵的"借用身份"。
//
// 每台共享平板上，每位机组各持有独立密钥，各用各自 PIN 保护。

import Foundation
import EFBCore
import EFBCryptography

/// 阶段 1 的产物：设备已生成、尚未绑证书的密钥。
public struct PendingCredentialKey: @unchecked Sendable {
    public let crew: CrewID
    public let blob: Data
    public let protection: KeyProtection
    public let publicKeyX963: Data
    /// 解锁密钥：解开硬件签字密钥所需，阶段 3 用它建立 PIN 包裹。
    public let secret: SecureBytes

    public init(crew: CrewID, blob: Data, protection: KeyProtection, publicKeyX963: Data, secret: SecureBytes) {
        self.crew = crew
        self.blob = blob
        self.protection = protection
        self.publicKeyX963 = publicKeyX963
        self.secret = secret
    }
}

public final class CrewEnroller: @unchecked Sendable {
    private let store: CrewCredentialStore
    private let deviceID: DeviceID
    private let policy: CrewPolicy
    private let time: TrustedTimeProviding
    private let keyVault: SigningKeyVault

    public init(
        store: CrewCredentialStore,
        deviceID: DeviceID,
        policy: CrewPolicy,
        time: TrustedTimeProviding,
        keyVault: SigningKeyVault = SecureEnclaveKeyVault()
    ) {
        self.store = store
        self.deviceID = deviceID
        self.policy = policy
        self.time = time
        self.keyVault = keyVault
    }

    /// 阶段 1：生成该机组在本机的签字密钥。公钥交给公司签证书。
    public func prepareKey(crew: CrewID, pin: SecureBytes) throws -> PendingCredentialKey {
        try PINAttemptTracker.validatePolicy(pin: pin, policy: policy)
        // 生成随机解锁密钥；PIN 不直接参与硬件密钥的门禁，改 PIN 不影响密钥与证书。
        let secret = SecureBytes((0..<32).map { _ in UInt8.random(in: 0...255) })
        let (handle, blob) = try keyVault.generate(secret: secret)
        guard !handle.publicKeyX963.isEmpty else {
            throw EFBError.keyUnavailable(reason: "生成的签字密钥没有公钥")
        }
        return PendingCredentialKey(
            crew: crew,
            blob: blob,
            protection: handle.protection,
            publicKeyX963: handle.publicKeyX963,
            secret: secret
        )
    }

    /// 阶段 3：装证书并落盘。证书里的公钥必须正是该设备这把密钥。
    public func enroll(
        crew: CrewID,
        role: CrewRole,
        seats: [Seat],
        pin: SecureBytes,
        certificate: IssuedCrewCertificate,
        revocationEpoch: Int,
        key: PendingCredentialKey
    ) throws -> CrewCredentialRecord {
        let now = try time.currentEpoch()

        // a) 证书必须由公司签发，且绑定本机、本人
        guard certificate.certificate.crewID == crew, certificate.certificate.deviceID == deviceID else {
            throw EFBError.credentialInvalid(reason: "证书绑定的机组或设备与本机不符")
        }
        guard key.crew == crew else {
            throw EFBError.keyBindingMismatch(reason: "待用密钥属于 \(key.crew)，并非 \(crew)")
        }

        // b) 证书公钥 == 本机持有的密钥公钥（脱钩即拒绝）
        guard certificate.certificate.signingPublicKeyX963 == key.publicKeyX963 else {
            throw EFBError.keyBindingMismatch(
                reason: "证书公钥与本机密钥不一致（证书指纹 \(SHA256Digest(hashing: certificate.certificate.signingPublicKeyX963).hexString.prefix(12))"
            )
        }

        // c) PIN 策略与座位资格
        try PINAttemptTracker.validatePolicy(pin: pin, policy: policy)
        for seat in seats where !certificate.certificate.covers(seat) {
            throw EFBError.roleNotPermitted(seat: seat, role: certificate.certificate.role)
        }

        // d) 密封密钥 + 密封载荷
        let sealingKey = try SecureEnclaveSealingKey.generate()
        let verifier = try PINHasher.makeVerifier(pin: pin, digits: pin.count)
        let previousHistory = (try? store.historyVerifiers(for: crew)) ?? []
        let wrapped = try PINWrap.wrap(key.secret, with: pin)
        let payload = SealedCredentialPayload(
            pinVerifier: verifier,
            pinHistory: Array(previousHistory.suffix(policy.pinHistoryDepth)),
            attemptState: .empty,
            createdAtEpoch: now,
            wrappedSigningSecret: wrapped.wrapped,
            wrapSalt: wrapped.salt,
            wrapIterations: wrapped.iterations
        )
        let sealed = try CredentialSealer.seal(try JSONEncoder().encode(payload), to: sealingKey.sealingPublicKeyX963)

        // e) 落盘
        let record = CrewCredentialRecord(
            crewID: crew,
            deviceID: deviceID,
            certificate: certificate,
            revocationEpoch: revocationEpoch,
            signingKeyBlob: key.blob,
            signingKeyProtection: key.protection,
            sealingKeyBlob: sealingKey.dataRepresentation,
            sealedPayload: sealed,
            lastUnlockEpoch: nil
        )
        try store.save(record)
        return record
    }

    /// 吊销某机组：删除本机凭据。权威撤销仍以公司撤销名单为准。
    public func revoke(crew: CrewID) throws {
        try store.delete(crew)
    }
}
