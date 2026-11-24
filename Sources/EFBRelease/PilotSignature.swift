// ReleaseRecord.swift
// 放行签字记录：离线产生的、可由公司离线核验的完整证据包。
//
// 一条签字包含：
//   * 被签内容（性能计算结果 / 放行单字段）的规范化摘要 —— 防止内容被换；
//   * 签字人证书 + 令牌序列号 —— 证明 "是谁、被公司授权做这件事"；
//   * 时间证明 —— 证明 "当时是几点"；
//   * 双人共签的交叉引用 —— 防止一人签两角；
//   * 审计链头哈希 + 设备侧状态摘要 —— 证明 "本机当时没有别的会话在动"。

import Foundation
import EFBCore
import EFBIdentity
import EFBCryptography

/// 被签的放行内容（示例字段，可按公司放行单扩展；只要都实现规范化即可）。
public struct ReleaseContent: Equatable, Sendable, CanonicalJSONEncodable, Codable {
    public let flightID: FlightID
    public let departure: String
    public let destination: String
    public let aircraftRegistration: String
    public let takeoffWeightKg: Int
    public let vSpeedsKt: [Int]
    public let runway: String
    public let computedAtEpoch: Double
    /// 性能计算输入的摘要（把 app 内计算链的原始输入绑定进来）。
    public let performanceInputDigest: SHA256Digest
    /// 燃油量（千克）。
    public let fuelKg: Int

    public init(
        flightID: FlightID,
        departure: String,
        destination: String,
        aircraftRegistration: String,
        takeoffWeightKg: Int,
        vSpeedsKt: [Int],
        runway: String,
        computedAtEpoch: Double,
        performanceInputDigest: SHA256Digest,
        fuelKg: Int
    ) {
        self.flightID = flightID
        self.departure = departure
        self.destination = destination
        self.aircraftRegistration = aircraftRegistration
        self.takeoffWeightKg = takeoffWeightKg
        self.vSpeedsKt = vSpeedsKt
        self.runway = runway
        self.computedAtEpoch = computedAtEpoch
        self.performanceInputDigest = performanceInputDigest
        self.fuelKg = fuelKg
    }

    public var canonicalValue: CanonicalValue {
        .object([
            "aircraftRegistration": .string(aircraftRegistration),
            "computedAtEpoch": .int(Int(computedAtEpoch)),
            "departure": .string(departure),
            "destination": .string(destination),
            "flightID": .string(flightID.rawValue),
            "fuelKg": .int(fuelKg),
            "performanceInputDigest": .string(performanceInputDigest.hexString),
            "runway": .string(runway),
            "takeoffWeightKg": .int(takeoffWeightKg),
            "vSpeedsKt": .array(vSpeedsKt.map { .int($0) }),
        ])
    }
}

/// 单个签字人的证据。
public struct PilotSignature: Equatable, Sendable, CanonicalJSONEncodable, Codable {
    public let crewID: CrewID
    public let seat: Seat
    public let role: CrewRole
    public let certificateID: CertificateID
    /// 证书里的公钥（便于审计工具脱离设备离线验签）。
    public let signingPublicKeyX963: Data
    public let tokenSerial: TokenSerial
    public let sessionID: SessionID
    public let signedAtEpoch: Double
    public let timeAttestation: TimeAttestation
    public let presenceFactor: PresenceFactor
    /// 签字时密钥的硬件强度（SE / software），公司据此评估置信度。
    public let hardwareBacked: Bool
    /// 签字密钥保护级别。
    public let keyProtection: KeyProtection
    /// 会话租约内最近一次解锁的 epoch。
    public let unlockedAtEpoch: Double
    /// 审计链在签字前一刻的头哈希。
    public let auditHead: SHA256Digest
    /// 被签内容的规范化摘要（签名覆盖的就是它）。
    public let contentDigest: SHA256Digest
    /// ECDSA-SHA256(P 被签载荷) 的 DER 签名。被签载荷本身由下面 buildSignedPayload 定义。
    public let signatureDER: Data
    /// 被签载荷的完整规范化字节，原样随包上行，便于公司离线重算。
    public let signedPayloadBytes: Data

    public init(
        crewID: CrewID,
        seat: Seat,
        role: CrewRole,
        certificateID: CertificateID,
        signingPublicKeyX963: Data,
        tokenSerial: TokenSerial,
        sessionID: SessionID,
        signedAtEpoch: Double,
        timeAttestation: TimeAttestation,
        presenceFactor: PresenceFactor,
        hardwareBacked: Bool,
        keyProtection: KeyProtection,
        unlockedAtEpoch: Double,
        auditHead: SHA256Digest,
        contentDigest: SHA256Digest,
        signatureDER: Data,
        signedPayloadBytes: Data
    ) {
        self.crewID = crewID
        self.seat = seat
        self.role = role
        self.certificateID = certificateID
        self.signingPublicKeyX963 = signingPublicKeyX963
        self.tokenSerial = tokenSerial
        self.sessionID = sessionID
        self.signedAtEpoch = signedAtEpoch
        self.timeAttestation = timeAttestation
        self.presenceFactor = presenceFactor
        self.hardwareBacked = hardwareBacked
        self.keyProtection = keyProtection
        self.unlockedAtEpoch = unlockedAtEpoch
        self.auditHead = auditHead
        self.contentDigest = contentDigest
        self.signatureDER = signatureDER
        self.signedPayloadBytes = signedPayloadBytes
    }

    public var canonicalValue: CanonicalValue {
        .object([
            "auditHead": .string(auditHead.hexString),
            "certificateID": .string(certificateID.rawValue),
            "contentDigest": .string(contentDigest.hexString),
            "crewID": .string(crewID.rawValue),
            "hardwareBacked": .bool(hardwareBacked),
            "keyProtection": .string(keyProtection.rawValue),
            "presenceFactor": .string(presenceFactor.rawValue),
            "role": .string(role.rawValue),
            "seat": .string(seat.rawValue),
            "sessionID": .string(sessionID.rawValue),
            "signatureDER": .string(signatureDER.base64EncodedString()),
            "signedAtEpoch": .int(Int(signedAtEpoch)),
            "signedPayloadBytes": .string(signedPayloadBytes.base64EncodedString()),
            "signingPublicKeyX963": .string(signingPublicKeyX963.base64EncodedString()),
            "timeAttestation": timeAttestation.canonicalValue,
            "tokenSerial": .string(tokenSerial.rawValue),
            "unlockedAtEpoch": .int(Int(unlockedAtEpoch)),
        ])
    }

    /// 被签载荷：机组成员 + 座位 + 令牌 + 内容 + 时间 + 审计头。
    /// 这个集合一旦被改动，签名即失效。
    public static func buildSignedPayload(
        content: ReleaseContent,
        crew: CrewID,
        seat: Seat,
        tokenSerial: TokenSerial,
        sessionID: SessionID,
        signedAtEpoch: Double,
        timeAttestation: TimeAttestation,
        auditHead: SHA256Digest,
        presenceFactor: PresenceFactor,
        certificateID: CertificateID,
        hardwareBacked: Bool,
        keyProtection: KeyProtection
    ) -> CanonicalValue {
        .object([
            "auditHead": .string(auditHead.hexString),
            // 密钥强度必须进入被签载荷，否则设备把 software 改成 hardware 即可骗过审计。
            "hardwareBacked": .bool(hardwareBacked),
            "keyProtection": .string(keyProtection.rawValue),
            "certificateID": .string(certificateID.rawValue),
            "contentDigest": .string(content.canonicalSHA256.hexString),
            "crewID": .string(crew.rawValue),
            "presenceFactor": .string(presenceFactor.rawValue),
            "seat": .string(seat.rawValue),
            "sessionID": .string(sessionID.rawValue),
            "signedAtEpoch": .int(Int(signedAtEpoch)),
            "timeAttestation": timeAttestation.canonicalValue,
            "tokenSerial": .string(tokenSerial.rawValue),
            "version": .string("EFB-RELEASE-SIG-V1"),
        ])
    }
}

/// 双人签字记录。
public struct ReleaseRecord: Equatable, Sendable, CanonicalJSONEncodable, Codable {
    public let recordID: String
    public let flightID: FlightID
    public let content: ReleaseContent
    public let purpose: ReleasePurpose
    public let deviceID: DeviceID
    public let signatures: [PilotSignature]
    /// 整本审计链（含登机、交接、核验、签发 grant 的每一笔）。落地后随包上传。
    public let auditLog: AuditLog
    /// 本记录完成后，取证链的摘要（签字者 / 内容 / 审计头）。
    public let sealedDigest: SHA256Digest

    public init(
        recordID: String,
        flightID: FlightID,
        content: ReleaseContent,
        purpose: ReleasePurpose,
        deviceID: DeviceID,
        signatures: [PilotSignature],
        auditLog: AuditLog,
        sealedDigest: SHA256Digest
    ) {
        self.recordID = recordID
        self.flightID = flightID
        self.content = content
        self.purpose = purpose
        self.deviceID = deviceID
        self.signatures = signatures
        self.auditLog = auditLog
        self.sealedDigest = sealedDigest
    }

    public var canonicalValue: CanonicalValue {
        .object([
            "auditLogHead": .string(auditLog.headHash.hexString),
            "content": content.canonicalValue,
            "deviceID": .string(deviceID.rawValue),
            "flightID": .string(flightID.rawValue),
            "purpose": .string(purpose.rawValue),
            "recordID": .string(recordID),
            "sealedDigest": .string(sealedDigest.hexString),
            "signatures": .array(signatures.map { $0.canonicalValue }),
        ])
    }

    public var signedBy: [CrewID] { signatures.map(\.crewID) }

    public func signature(for seat: Seat) -> PilotSignature? {
        signatures.first { $0.seat == seat }
    }
}
