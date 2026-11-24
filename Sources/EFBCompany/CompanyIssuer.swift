// CompanyIssuer.swift
// 公司侧工具：离线预置材料的唯一来源。
//
// 这些能力绝不应编译进平板上的 EFB 应用 —— 平板只接收已签发的证书与令牌。
// 因此它们单独放在 EFBCompany 目标里，只用于：
//   * 航空公司 IT 的签发系统；
//   * 落地后的审计工具；
//   * 本仓库的测试与演示。
//
// 根私钥只存在于公司 HSM 中；这里用内存密钥模拟，调用方可替换为 HSM 抽象。

import Foundation
import EFBCore
import EFBIdentity
import EFBCryptography
import EFBRelease
import EFBSession
import EFBProvisioning

public struct SigningAuthority: @unchecked Sendable {
    public let anchor: TrustAnchor
    private let rootKey: SoftwareSigningKey
    private var currentEpochProvider: () -> Double

    public init(anchorID: String, currentEpochProvider: @escaping () -> Double) throws {
        let key = SoftwareSigningKey()
        self.rootKey = key
        // 根有效期给 5 年
        self.anchor = TrustAnchor(
            anchorID: anchorID,
            publicKeyX963: key.publicKeyX963,
            notBeforeEpoch: currentEpochProvider() - 86400,
            notAfterEpoch: currentEpochProvider() + 5 * 365 * 86400,
            purposes: ["crew-certificate", "issuer-delegation", "revocation", "release-token", "takeover"]
        )
        self.currentEpochProvider = currentEpochProvider
    }

    /// 用同一把根密钥恢复（持久化在测试里用）。
    public init(anchor: TrustAnchor, rootPrivateKey: Data, currentEpochProvider: @escaping () -> Double) throws {
        self.anchor = anchor
        self.rootKey = try SoftwareSigningKey(rawPrivateKey: rootPrivateKey)
        self.currentEpochProvider = currentEpochProvider
    }

    public var rootPrivateKey: Data { rootKey.rawPrivateKey }

    public func signerID() -> String { anchor.anchorID }

    /// 签一个任意规范化载荷，返回信封。
    public func signEnvelope<Content: CanonicalJSONEncodable>(_ content: Content) throws -> SignatureEnvelope {
        let bytes = content.canonicalBytes
        let signature = try rootKey.sign(bytes, reason: "公司签发")
        return SignatureEnvelope(
            signerID: anchor.anchorID,
            digest: SHA256Digest(hashing: content),
            signatureDER: signature,
            signedAtEpoch: currentEpochProvider()
        )
    }

    // MARK: 签发者

    public func delegateIssuer(
        issuerID: String,
        allowedRoles: [CrewRole],
        validitySeconds: Double = 365 * 86400
    ) throws -> (IssuerRecord, SoftwareSigningKey) {
        let key = SoftwareSigningKey()
        let now = currentEpochProvider()
        var record = IssuerRecord(
            issuerID: issuerID,
            publicKeyX963: key.publicKeyX963,
            allowedRoles: allowedRoles,
            notBeforeEpoch: now - 3600,
            notAfterEpoch: now + validitySeconds,
            envelope: SignatureEnvelope(signerID: anchor.anchorID, digest: .zero, signatureDER: Data(), signedAtEpoch: now)
        )
        record = IssuerRecord(
            issuerID: record.issuerID,
            publicKeyX963: record.publicKeyX963,
            allowedRoles: record.allowedRoles,
            notBeforeEpoch: record.notBeforeEpoch,
            notAfterEpoch: record.notAfterEpoch,
            envelope: SignatureEnvelope(
                signerID: anchor.anchorID,
                digest: record.signedContent.canonicalSHA256,
                signatureDER: try rootKey.sign(record.signedContent.canonicalBytes, reason: "委托签发者"),
                signedAtEpoch: now
            )
        )
        return (record, key)
    }

    // MARK: 机组成员证书

    public func issueCrewCertificate(
        crew: CrewID,
        device: DeviceID,
        signingPublicKeyX963: Data,
        role: CrewRole,
        seats: [Seat],
        policyDigest: SHA256Digest,
        revocationEpoch: Int,
        validitySeconds: Double = 90 * 86400,
        issuerID: String,
        issuerKey: SoftwareSigningKey
    ) throws -> IssuedCrewCertificate {
        let now = currentEpochProvider()
        let certificateID = try CertificateID(validating: "C-" + crew.rawValue + "-" + String(fingerprint(signingPublicKeyX963).prefix(10)))
        let certificate = CrewCertificate(
            certificateID: certificateID,
            crewID: crew,
            deviceID: device,
            signingPublicKeyX963: signingPublicKeyX963,
            role: role,
            seatQualifications: seats,
            notBeforeEpoch: now - 3600,
            notAfterEpoch: now + validitySeconds,
            anchorID: anchor.anchorID,
            policyDigest: policyDigest,
            revocationEpoch: revocationEpoch
        )
        let signature = try issuerKey.sign(certificate.canonicalBytes, reason: "签发机组证书")
        let envelope = SignatureEnvelope(
            signerID: issuerID,
            digest: SHA256Digest(hashing: certificate),
            signatureDER: signature,
            signedAtEpoch: now
        )
        return IssuedCrewCertificate(
            certificate: certificate,
            issuerID: issuerID,
            issuerPublicKeyX963: issuerKey.publicKeyX963,
            envelope: envelope
        )
    }

    // MARK: 撤销快照

    public func issueRevocationSnapshot(
        epoch: Int,
        revokedCertificates: [CertificateID],
        revokedCrew: [CrewID],
        validitySeconds: Double = 14 * 86400,
        issuerID: String,
        issuerKey: SoftwareSigningKey
    ) throws -> RevocationSnapshot {
        let now = currentEpochProvider()
        let draft = RevocationSnapshot(
            epoch: epoch,
            issuedAtEpoch: now,
            validUntilEpoch: now + validitySeconds,
            revokedCertificateIDs: revokedCertificates,
            revokedCrewIDs: revokedCrew,
            issuerID: issuerID,
            issuerPublicKeyX963: issuerKey.publicKeyX963,
            envelope: SignatureEnvelope(signerID: issuerID, digest: .zero, signatureDER: Data(), signedAtEpoch: now)
        )
        return RevocationSnapshot(
            epoch: epoch,
            issuedAtEpoch: now,
            validUntilEpoch: draft.validUntilEpoch,
            revokedCertificateIDs: revokedCertificates,
            revokedCrewIDs: revokedCrew,
            issuerID: issuerID,
            issuerPublicKeyX963: issuerKey.publicKeyX963,
            envelope: SignatureEnvelope(
                signerID: issuerID,
                digest: draft.signedContent.canonicalSHA256,
                signatureDER: try issuerKey.sign(draft.signedContent.canonicalBytes, reason: "签发撤销名单"),
                signedAtEpoch: now
            )
        )
    }

    // MARK: 放行令牌

    public func issueReleaseTokens(
        flight: FlightID,
        crewAssignments: [(crew: CrewID, seat: Seat, device: DeviceID)],
        purpose: ReleasePurpose,
        fromEpoch: Double,
        untilEpoch: Double,
        issuerID: String,
        issuerKey: SoftwareSigningKey
    ) throws -> [ReleaseToken] {
        var tokens: [ReleaseToken] = []
        for (index, assignment) in crewAssignments.enumerated() {
            let serial = try TokenSerial(validating: "TK-" + flight.rawValue.prefix(20) + "-" + String(format: "%03d", index + 1))
            let draft = ReleaseToken(
                serial: serial,
                flightID: flight,
                crewID: assignment.crew,
                seat: assignment.seat,
                deviceID: assignment.device,
                validFromEpoch: fromEpoch,
                validUntilEpoch: untilEpoch,
                issuerID: issuerID,
                issuerPublicKeyX963: issuerKey.publicKeyX963,
                purpose: purpose,
                envelope: SignatureEnvelope(signerID: issuerID, digest: .zero, signatureDER: Data(), signedAtEpoch: currentEpochProvider())
            )
            let now = currentEpochProvider()
            tokens.append(ReleaseToken(
                serial: draft.serial,
                flightID: draft.flightID,
                crewID: draft.crewID,
                seat: draft.seat,
                deviceID: draft.deviceID,
                validFromEpoch: draft.validFromEpoch,
                validUntilEpoch: draft.validUntilEpoch,
                issuerID: draft.issuerID,
                issuerPublicKeyX963: draft.issuerPublicKeyX963,
                purpose: draft.purpose,
                envelope: SignatureEnvelope(
                    signerID: issuerID,
                    digest: draft.signedContent.canonicalSHA256,
                    signatureDER: try issuerKey.sign(draft.signedContent.canonicalBytes, reason: "签发放行令牌"),
                    signedAtEpoch: now
                )
            ))
        }
        return tokens
    }

    // MARK: 预置包

    /// 生成并签名一个本场预置包（由公司根签名）。
    public func issueBootstrapPackage(
        deviceID: DeviceID,
        timeAnchor: TimeAnchor,
        issuers: [IssuerRecord],
        revocation: RevocationSnapshot,
        tokens: [ReleaseToken],
        policy: CrewPolicy
    ) throws -> BootstrapPackage {
        let draft = BootstrapPackage(
            deviceID: deviceID, anchor: timeAnchor, issuers: issuers,
            revocation: revocation, tokens: tokens, policy: policy,
            envelope: SignatureEnvelope(signerID: anchor.anchorID, digest: .zero, signatureDER: Data(),
                                        signedAtEpoch: currentEpochProvider())
        )
        return BootstrapPackage(
            deviceID: deviceID, anchor: timeAnchor, issuers: issuers,
            revocation: revocation, tokens: tokens, policy: policy,
            envelope: SignatureEnvelope(
                signerID: anchor.anchorID,
                digest: draft.signedContent.canonicalSHA256,
                signatureDER: try rootKey.sign(draft.signedContent.canonicalBytes, reason: "签发预置包"),
                signedAtEpoch: currentEpochProvider()
            )
        )
    }

    // MARK: 接管授权

    public func issueTakeoverAuthorization(
        authorizationID: String,
        device: DeviceID,
        seat: Seat,
        subjectCrew: CrewID?,
        validitySeconds: Double = 2 * 3600,
        issuerID: String,
        issuerKey: SoftwareSigningKey
    ) throws -> TakeoverAuthorization {
        let now = currentEpochProvider()
        let draft = TakeoverAuthorization(
            authorizationID: authorizationID,
            deviceID: device,
            seat: seat,
            subjectCrew: subjectCrew,
            issuedAtEpoch: now,
            expiresAtEpoch: now + validitySeconds,
            issuerID: issuerID,
            issuerPublicKeyX963: issuerKey.publicKeyX963,
            envelope: SignatureEnvelope(signerID: issuerID, digest: .zero, signatureDER: Data(), signedAtEpoch: now)
        )
        return TakeoverAuthorization(
            authorizationID: draft.authorizationID,
            deviceID: draft.deviceID,
            seat: draft.seat,
            subjectCrew: draft.subjectCrew,
            issuedAtEpoch: draft.issuedAtEpoch,
            expiresAtEpoch: draft.expiresAtEpoch,
            issuerID: draft.issuerID,
            issuerPublicKeyX963: draft.issuerPublicKeyX963,
            envelope: SignatureEnvelope(
                signerID: issuerID,
                digest: draft.signedContent.canonicalSHA256,
                signatureDER: try issuerKey.sign(draft.signedContent.canonicalBytes, reason: "签发接管授权"),
                signedAtEpoch: now
            )
        )
    }

    /// 公钥指纹（SHA-256 前 10 字节的十六进制），用于生成证书标识。
    public func fingerprint(_ publicKey: Data) -> String {
        SHA256Digest(hashing: publicKey).hexString
    }
}
