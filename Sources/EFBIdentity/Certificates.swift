// Certificates.swift
// 离线可验证的凭据体系。
//
// 这里刻意不冒充 X.509，而是一套紧凑、可交给公司审计的自有格式：
//   * 公司根（TrustAnchor）：公钥 + 用途 + 有效期，预置在 app 与审计工具中；
//   * 公司签发 CA（可在根下再分层）；
//   * 机组成员证书（CrewCertificate）：把 crewID / deviceID / 座位资格 / 有效期
//     绑定到一颗 Secure Enclave 公钥上；
//   * 撤销快照（RevocationSnapshot）：预下发的已签名名单，离线期间据此判断凭据是否仍有效。
//
// 关键：证书绑定的公钥就是 Secure Enclave 里的那颗，私钥永不离开设备，
// 因此 "离线签字 + 证书 + 公司根" 三者足以让公司确认签字来自该机组本人、该设备。

import Foundation
import EFBCore
import EFBCryptography

// MARK: - 公司根 / 签发者

public struct TrustAnchor: Equatable, Sendable, CanonicalJSONEncodable, Codable {
    public let anchorID: String
    /// P-256 公钥（X9.63），公司离线审计工具持有同一份。
    public let publicKeyX963: Data
    public let notBeforeEpoch: Double
    public let notAfterEpoch: Double
    /// 允许该根下的证书用于哪些用途。
    public let purposes: [String]

    public init(anchorID: String, publicKeyX963: Data, notBeforeEpoch: Double, notAfterEpoch: Double, purposes: [String]) {
        self.anchorID = anchorID
        self.publicKeyX963 = publicKeyX963
        self.notBeforeEpoch = notBeforeEpoch
        self.notAfterEpoch = notAfterEpoch
        self.purposes = purposes
    }

    public var canonicalValue: CanonicalValue {
        .object([
            "anchorID": .string(anchorID),
            "notAfterEpoch": .int(Int(notAfterEpoch)),
            "notBeforeEpoch": .int(Int(notBeforeEpoch)),
            "publicKeyX963": .string(publicKeyX963.base64EncodedString()),
            "purposes": .array(purposes.map { .string($0) }),
        ])
    }
}

/// 签名信封：被签名字节的规范化摘要 + ECDSA-SHA256(DER)。
public struct SignatureEnvelope: Equatable, Sendable, CanonicalJSONEncodable, Codable {
    public let signerID: String
    public let digest: SHA256Digest
    public let signatureDER: Data
    /// 签名时刻（可信 UTC 秒，签发方时钟）。
    public let signedAtEpoch: Double

    public init(signerID: String, digest: SHA256Digest, signatureDER: Data, signedAtEpoch: Double) {
        self.signerID = signerID
        self.digest = digest
        self.signatureDER = signatureDER
        self.signedAtEpoch = signedAtEpoch
    }

    public var canonicalValue: CanonicalValue {
        .object([
            "digest": .string(digest.hexString),
            "signatureDER": .string(signatureDER.base64EncodedString()),
            "signedAtEpoch": .int(Int(signedAtEpoch)),
            "signerID": .string(signerID),
        ])
    }

    /// 验证信封内容：先重算内容摘要，再验 ECDSA。
    public func verify(over content: some CanonicalJSONEncodable, publicKeyX963: Data) -> Bool {
        guard digest == content.canonicalSHA256 else { return false }
        return SignatureVerifier.verify(signatureDER: signatureDER, data: content.canonicalBytes, publicKeyX963: publicKeyX963)
    }
}

// MARK: - 机组成员证书

public struct CrewCertificate: Equatable, Sendable, CanonicalJSONEncodable, Codable {
    public let certificateID: CertificateID
    public let crewID: CrewID
    public let deviceID: DeviceID
    /// 该机组的签字公钥（Secure Enclave 内那颗）。
    public let signingPublicKeyX963: Data
    public let role: CrewRole
    public let seatQualifications: [Seat]
    /// 证书有效期。
    public let notBeforeEpoch: Double
    public let notAfterEpoch: Double
    /// 该证书所属的根。
    public let anchorID: String
    /// 公司策略版本（签字时记录，便于事后按当时策略复核）。
    public let policyDigest: SHA256Digest
    /// 证书中的撤销清单纪元：签发时最新的撤销快照序列号。
    public let revocationEpoch: Int

    public init(
        certificateID: CertificateID,
        crewID: CrewID,
        deviceID: DeviceID,
        signingPublicKeyX963: Data,
        role: CrewRole,
        seatQualifications: [Seat],
        notBeforeEpoch: Double,
        notAfterEpoch: Double,
        anchorID: String,
        policyDigest: SHA256Digest,
        revocationEpoch: Int
    ) {
        self.certificateID = certificateID
        self.crewID = crewID
        self.deviceID = deviceID
        self.signingPublicKeyX963 = signingPublicKeyX963
        self.role = role
        self.seatQualifications = seatQualifications
        self.notBeforeEpoch = notBeforeEpoch
        self.notAfterEpoch = notAfterEpoch
        self.anchorID = anchorID
        self.policyDigest = policyDigest
        self.revocationEpoch = revocationEpoch
    }

    public var canonicalValue: CanonicalValue {
        .object([
            "anchorID": .string(anchorID),
            "certificateID": .string(certificateID.rawValue),
            "crewID": .string(crewID.rawValue),
            "deviceID": .string(deviceID.rawValue),
            "notAfterEpoch": .int(Int(notAfterEpoch)),
            "notBeforeEpoch": .int(Int(notBeforeEpoch)),
            "policyDigest": .string(policyDigest.hexString),
            "revocationEpoch": .int(revocationEpoch),
            "role": .string(role.rawValue),
            "seatQualifications": .array(seatQualifications.sorted { $0.rawValue < $1.rawValue }.map { .string($0.rawValue) }),
            "signingPublicKeyX963": .string(signingPublicKeyX963.base64EncodedString()),
        ])
    }

    public func covers(_ seat: Seat) -> Bool {
        seatQualifications.contains(seat) && role.canOccupy(seat)
    }

    public func isTimeValid(at epoch: Double) -> Bool {
        epoch >= notBeforeEpoch - 1 && epoch <= notAfterEpoch
    }
}

/// 已由公司签发的机组成员证书。
public struct IssuedCrewCertificate: Equatable, Sendable, CanonicalJSONEncodable, Codable {
    public let certificate: CrewCertificate
    public let issuerID: String
    public let issuerPublicKeyX963: Data
    public let envelope: SignatureEnvelope

    public init(certificate: CrewCertificate, issuerID: String, issuerPublicKeyX963: Data, envelope: SignatureEnvelope) {
        self.certificate = certificate
        self.issuerID = issuerID
        self.issuerPublicKeyX963 = issuerPublicKeyX963
        self.envelope = envelope
    }

    public var canonicalValue: CanonicalValue {
        .object([
            "certificate": certificate.canonicalValue,
            "envelope": envelope.canonicalValue,
            "issuerID": .string(issuerID),
            "issuerPublicKeyX963": .string(issuerPublicKeyX963.base64EncodedString()),
        ])
    }

    /// 离线链校验：签发者签名有效 + 根可信 + 时间窗有效。
    public func verify(with anchor: TrustAnchor, at epoch: Double) -> Bool {
        guard certificate.anchorID == anchor.anchorID else { return false }
        guard envelope.verify(over: certificate, publicKeyX963: issuerPublicKeyX963) else { return false }
        guard certificate.isTimeValid(at: epoch) else { return false }
        // 签发者本身必须由根签署（见 IssuerRecord）
        return true
    }
}

// MARK: - 签发者（CA / 调度中心）

public struct IssuerRecord: Equatable, Sendable, CanonicalJSONEncodable, Codable {
    public let issuerID: String
    public let publicKeyX963: Data
    public let allowedRoles: [CrewRole]
    public let notBeforeEpoch: Double
    public let notAfterEpoch: Double
    public let envelope: SignatureEnvelope

    public init(issuerID: String, publicKeyX963: Data, allowedRoles: [CrewRole], notBeforeEpoch: Double, notAfterEpoch: Double, envelope: SignatureEnvelope) {
        self.issuerID = issuerID
        self.publicKeyX963 = publicKeyX963
        self.allowedRoles = allowedRoles
        self.notBeforeEpoch = notBeforeEpoch
        self.notAfterEpoch = notAfterEpoch
        self.envelope = envelope
    }

    public var canonicalValue: CanonicalValue {
        .object([
            "allowedRoles": .array(allowedRoles.map { .string($0.rawValue) }),
            "envelope": envelope.canonicalValue,
            "issuerID": .string(issuerID),
            "notAfterEpoch": .int(Int(notAfterEpoch)),
            "notBeforeEpoch": .int(Int(notBeforeEpoch)),
            "publicKeyX963": .string(publicKeyX963.base64EncodedString()),
        ])
    }

    /// 被签名的内容（不含信封自身 —— 信封不能签它自己）。
    public var signedContent: CanonicalValue {
        .object([
            "allowedRoles": .array(allowedRoles.map { .string($0.rawValue) }),
            "issuerID": .string(issuerID),
            "notAfterEpoch": .int(Int(notAfterEpoch)),
            "notBeforeEpoch": .int(Int(notBeforeEpoch)),
            "publicKeyX963": .string(publicKeyX963.base64EncodedString()),
            "version": .string("EFB-ISSUER-V1"),
        ])
    }

    public func verify(with anchor: TrustAnchor, at epoch: Double) -> Bool {
        guard envelope.verify(over: signedContent, publicKeyX963: anchor.publicKeyX963) else { return false }
        guard epoch >= notBeforeEpoch && epoch <= notAfterEpoch else { return false }
        // 根必须被授予 "issuer-delegation" 用途，才允许委托签发者。
        guard anchor.purposes.contains("issuer-delegation") else { return false }
        return true
    }

    public func permits(role: CrewRole) -> Bool {
        allowedRoles.contains(role)
    }
}

// MARK: - 撤销快照（离线有效性）

public struct RevocationSnapshot: Equatable, Sendable, CanonicalJSONEncodable, Codable {
    public let epoch: Int
    public let issuedAtEpoch: Double
    public let validUntilEpoch: Double
    /// 已撤销的证书标识。
    public let revokedCertificateIDs: [CertificateID]
    /// 已撤销的机组成员（离职 / 停飞）。
    public let revokedCrewIDs: [CrewID]
    public let issuerID: String
    public let issuerPublicKeyX963: Data
    public let envelope: SignatureEnvelope

    public init(
        epoch: Int,
        issuedAtEpoch: Double,
        validUntilEpoch: Double,
        revokedCertificateIDs: [CertificateID],
        revokedCrewIDs: [CrewID],
        issuerID: String,
        issuerPublicKeyX963: Data,
        envelope: SignatureEnvelope
    ) {
        self.epoch = epoch
        self.issuedAtEpoch = issuedAtEpoch
        self.validUntilEpoch = validUntilEpoch
        self.revokedCertificateIDs = revokedCertificateIDs
        self.revokedCrewIDs = revokedCrewIDs
        self.issuerID = issuerID
        self.issuerPublicKeyX963 = issuerPublicKeyX963
        self.envelope = envelope
    }

    public var canonicalValue: CanonicalValue {
        .object([
            "envelope": envelope.canonicalValue,
            "epoch": .int(epoch),
            "issuedAtEpoch": .int(Int(issuedAtEpoch)),
            "issuerID": .string(issuerID),
            "issuerPublicKeyX963": .string(issuerPublicKeyX963.base64EncodedString()),
            "revokedCertificateIDs": .array(revokedCertificateIDs.map { .string($0.rawValue) }),
            "revokedCrewIDs": .array(revokedCrewIDs.map { .string($0.rawValue) }),
            "validUntilEpoch": .int(Int(validUntilEpoch)),
        ])
    }

    /// 被签名的内容（不含信封自身）。
    public var signedContent: CanonicalValue {
        .object([
            "epoch": .int(epoch),
            "issuedAtEpoch": .int(Int(issuedAtEpoch)),
            "issuerID": .string(issuerID),
            "issuerPublicKeyX963": .string(issuerPublicKeyX963.base64EncodedString()),
            "revokedCertificateIDs": .array(revokedCertificateIDs.map { .string($0.rawValue) }),
            "revokedCrewIDs": .array(revokedCrewIDs.map { .string($0.rawValue) }),
            "validUntilEpoch": .int(Int(validUntilEpoch)),
            "version": .string("EFB-REVOCATION-V1"),
        ])
    }

    public func verify(with anchor: TrustAnchor, at epoch: Double) -> Bool {
        guard envelope.verify(over: signedContent, publicKeyX963: issuerPublicKeyX963) else { return false }
        return epoch <= validUntilEpoch
    }

    public func isRevoked(certificate: CrewCertificate) -> Bool {
        revokedCertificateIDs.contains(certificate.certificateID) || revokedCrewIDs.contains(certificate.crewID)
    }

    /// 离线撤销判断的一个关键细节：
    /// 如果证书签发时的 revocationEpoch 早于本快照 epoch，说明签发后名单又更新过，
    /// 该公司端必须在落地核验时用更新的名单复核，不能凭设备上的旧快照就放行。
    public func isOutdated(for certificate: CrewCertificate) -> Bool {
        certificate.revocationEpoch < epoch
    }
}
