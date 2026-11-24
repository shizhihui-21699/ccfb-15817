// ReleaseSigner.swift
// 双人共签的签字入口。
//
// 一次放行需要正副驾驶在不同座位上各签一次；同一 CrewID 不允许占用两个座位。
// 两次签字通过 priorSignatureDigest 互锁：第二名签字人签的载荷里包含第一位
// 签字人的签名摘要，因此不能"先签后改内容"。

import Foundation
import EFBCore
import EFBIdentity
import EFBCryptography

public enum EFBReleaseError: Error, Equatable, Sendable {
    /// 同一人尝试签两个座位。
    case duplicateSigner(CrewID)
    /// 两名签字人之间超过策略允许的窗口。
    case intervalExceeded(seconds: Double)
}

/// 令牌的离线校验器（持有公司放行系统的公钥）。
public protocol ReleaseTokenVerifying: Sendable {
    func verify(
        _ token: ReleaseToken,
        flight: FlightID,
        crew: CrewID,
        seat: Seat,
        device: DeviceID,
        purpose: ReleasePurpose,
        at epoch: Double
    ) -> Bool
}

/// 基于签发者公钥的默认实现。
public struct IssuerKeyTokenVerifier: ReleaseTokenVerifying {
    private let trustedIssuerKeys: [String: Data]

    public init(trustedIssuerKeys: [String: Data]) {
        self.trustedIssuerKeys = trustedIssuerKeys
    }

    public func verify(
        _ token: ReleaseToken,
        flight: FlightID,
        crew: CrewID,
        seat: Seat,
        device: DeviceID,
        purpose: ReleasePurpose,
        at epoch: Double
    ) -> Bool {
        guard let key = trustedIssuerKeys[token.issuerID], key == token.issuerPublicKeyX963 else { return false }
        guard token.envelope.verify(over: token.signedContent, publicKeyX963: token.issuerPublicKeyX963) else { return false }
        guard token.flightID == flight, token.crewID == crew, token.seat == seat,
              token.deviceID == device, token.purpose == purpose else { return false }
        return epoch >= token.validFromEpoch && epoch <= token.validUntilEpoch
    }
}

/// 座位占用校验：签字时要求签字人当前确实坐在对应座位、且会话就是当前这个。
/// 用闭包而不是 EFBSession 类型，是为了保持 EFBRelease 不反向依赖 EFBSession。
public typealias SeatOccupancyCheck = @Sendable (_ crew: CrewID, _ seat: Seat, _ sessionID: SessionID) -> Bool

public final class ReleaseSigner: @unchecked Sendable {
    private let authenticator: CrewAuthenticator
    private let seatCheck: SeatOccupancyCheck?
    private let tokenStore: ReleaseTokenStore
    private let tokenVerifier: ReleaseTokenVerifying
    private let policy: CrewPolicy
    private let time: TrustedTimeProviding
    private let deviceID: DeviceID

    public init(
        authenticator: CrewAuthenticator,
        tokenStore: ReleaseTokenStore,
        tokenVerifier: ReleaseTokenVerifying,
        policy: CrewPolicy,
        time: TrustedTimeProviding,
        deviceID: DeviceID,
        seatCheck: SeatOccupancyCheck? = nil
    ) {
        self.authenticator = authenticator
        self.seatCheck = seatCheck
        self.tokenStore = tokenStore
        self.tokenVerifier = tokenVerifier
        self.policy = policy
        self.time = time
        self.deviceID = deviceID
    }

    public func newRecordID(flight: FlightID) -> String {
        "R-" + flight.rawValue + "-" + String(UUID().uuidString.prefix(10))
    }

    /// 签发一个 pilot 签字。
    /// - Parameter existingSignatures: 已有签字（第一名签字时为空；第二名必须为非空）。
    public func sign(
        session: UnlockedCrew,
        content: ReleaseContent,
        purpose: ReleasePurpose,
        recordID: String,
        existingSignatures: [PilotSignature],
        audit: inout AuditLog
    ) async throws -> PilotSignature {
        let now = try time.currentEpoch()
        try session.ensureActive(at: now)

        // 0) 签字人必须是当前坐在该座位上的活跃会话（防止用早已交接/登出的句柄签字）
        if let seatCheck, !seatCheck(session.crewID, session.seat, session.sessionID) {
            throw EFBError.sessionLocked(reason: "\(session.crewID) 当前不是 \(session.seat.displayName) 的活跃会话")
        }

        // 1) 同一人不得签两角
        if existingSignatures.contains(where: { $0.crewID == session.crewID }) {
            throw EFBReleaseError.duplicateSigner(session.crewID)
        }
        // 2) 双签间隔
        if let first = existingSignatures.first,
           now - first.signedAtEpoch > policy.maxIntervalBetweenSignaturesSeconds {
            throw EFBReleaseError.intervalExceeded(seconds: now - first.signedAtEpoch)
        }
        // 3) 座位不能重复
        if existingSignatures.contains(where: { $0.seat == session.seat }) {
            throw EFBError.roleNotPermitted(seat: session.seat, role: session.role)
        }

        // 4) 找属于该机组 / 航班 / 座位的未消耗令牌
        let candidates = tokenStore.available(
            for: session.crewID, flight: content.flightID, seat: session.seat, device: deviceID
        )
        guard let token = candidates.first(where: { !tokenStore.isConsumed($0.serial) }) else {
            throw EFBError.tokenNotAuthorized(reason: "本机没有 \(session.crewID) 于 \(session.seat.displayName) 的 \(purpose.displayName) 令牌")
        }
        guard tokenVerifier.verify(
            token, flight: content.flightID, crew: session.crewID, seat: session.seat,
            device: deviceID, purpose: purpose, at: now
        ) else {
            throw EFBError.tokenInvalid(reason: "令牌内容与本次操作不符，或已超出时间窗")
        }

        // 5) 现场核验并签发一次性 grant。
        //    这一步是 await（Face ID 有交互时长），期间可能发生交接 / 锁屏，
        //    因此 await 返回后必须重新校验会话、重取可信时间 —— 不能沿用旧值。
        let scope = "release:\(recordID):\(session.seat.rawValue)"
        var grant = try await authenticator.authorizeSignature(for: session, scope: scope, audit: &audit)
        let signedAt = try time.currentEpoch()
        try session.ensureActive(at: signedAt)
        try authenticator.consume(&grant, session: session, scope: scope, at: signedAt)

        // 6) 消耗令牌（与签名同一条同步流程，无 await 跨越）
        _ = try tokenStore.consume(token.serial, at: signedAt)
        audit.append(kind: .tokenConsumed, atEpoch: signedAt, crew: session.crewID, seat: session.seat,
                     detail: "serial=\(token.serial.rawValue)")

        // 7) 构造被签载荷（含前一位签字人的摘要，形成互锁）
        let attestation = try time.attestation(forEpoch: signedAt)
        let priorDigest = existingSignatures.last.map { SHA256Digest(hashing: $0) }
        var payload = PilotSignature.buildSignedPayload(
            content: content,
            crew: session.crewID,
            seat: session.seat,
            tokenSerial: token.serial,
            sessionID: session.sessionID,
            signedAtEpoch: signedAt,
            timeAttestation: attestation,
            auditHead: audit.headHash,
            presenceFactor: grant.presenceFactor,
            certificateID: session.certificate.certificateID,
            hardwareBacked: session.signingKey.isHardwareBacked,
            keyProtection: session.signingKey.protection
        )
        if let priorDigest {
            payload = .object([
                "payload": payload,
                "priorSignatureDigest": .string(priorDigest.hexString),
            ])
        }
        let payloadBytes = payload.canonicalBytes

        // 8) 交给 Secure Enclave 签名
        let signatureDER = try session.signingKey.sign(
            payloadBytes,
            reason: "\(session.crewID.rawValue) 签字：\(purpose.displayName)"
        )

        let pilotSignature = PilotSignature(
            crewID: session.crewID,
            seat: session.seat,
            role: session.role,
            certificateID: session.certificate.certificateID,
            signingPublicKeyX963: session.signingKey.publicKeyX963,
            tokenSerial: token.serial,
            sessionID: session.sessionID,
            signedAtEpoch: signedAt,
            timeAttestation: attestation,
            presenceFactor: grant.presenceFactor,
            hardwareBacked: session.signingKey.isHardwareBacked,
            keyProtection: session.signingKey.protection,
            unlockedAtEpoch: session.unlockedAtEpoch,
            auditHead: audit.headHash,
            contentDigest: content.canonicalSHA256,
            signatureDER: signatureDER,
            signedPayloadBytes: payloadBytes
        )
        audit.append(kind: .releaseSigned, atEpoch: signedAt, crew: session.crewID, seat: session.seat,
                     detail: "record=\(recordID) token=\(token.serial)")
        return pilotSignature
    }

    /// 两名不同机组成员签完后，封成可上传的记录。
    public func finalize(
        recordID: String,
        content: ReleaseContent,
        purpose: ReleasePurpose,
        signatures: [PilotSignature],
        audit: AuditLog
    ) throws -> ReleaseRecord {
        let expected = policy.requiresTwoPilotRelease ? 2 : 1
        guard signatures.count == expected else {
            throw EFBError.handoverIncomplete(reason: "签字人数 \(signatures.count) 不符（需要 \(expected)）")
        }
        let distinctCrew = Set(signatures.map { $0.crewID })
        guard distinctCrew.count == signatures.count else {
            throw EFBReleaseError.duplicateSigner(signatures[0].crewID)
        }
        for signature in signatures {
            guard signature.contentDigest == content.canonicalSHA256 else {
                throw EFBError.signatureInvalid(reason: "签字覆盖的内容与记录不一致")
            }
        }
        // sealedDigest 必须覆盖审计链头，否则删除/伪造链尾事件不会被发现。
        let sealed = SHA256Digest(hashing: CanonicalValue.object([
            "auditHead": .string(audit.headHash.hexString),
            "content": .string(content.canonicalSHA256.hexString),
            "recordID": .string(recordID),
            "signatures": .array(signatures.map { .string(SHA256Digest(hashing: $0).hexString) }),
        ]))
        return ReleaseRecord(
            recordID: recordID,
            flightID: content.flightID,
            content: content,
            purpose: purpose,
            deviceID: deviceID,
            signatures: signatures,
            auditLog: audit,
            sealedDigest: sealed
        )
    }
}
