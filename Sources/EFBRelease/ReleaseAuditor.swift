// ReleaseAuditor.swift
// 公司侧离线核验。落地后上传 ReleaseRecord，公司无需信任平板，只凭公开材料核对。
//
// 核验分四层，任何一层不通过即拒绝：
//
//   A. 证据完整性
//      1. 每个签字的 signedPayloadBytes 必须与从记录各字段重建的载荷逐字节相同；
//      2. contentDigest 必须等于 ReleaseContent 的规范化摘要；
//      3. 用签字人证书公钥验 ECDSA；
//      4. sealedDigest 必须等于记录的重算值。
//
//   B. 身份与授权
//      5. 证书链到公司根（离线，根公钥预置）；
//      6. 证书未过期且在签字时刻有效；
//      7. 证书绑定的 crewID / deviceID / seat 与签字记录一致；
//      8. 令牌序列号确实由公司签发给了这位机组、这一航班、这一座位，
//         且未出现在已消耗清单里（公司端看到的就是唯一一次）。
//
//   C. 双人与互锁
//      9. 两名签字人必须是不同的 crewID，且分别占左右座；
//     10. 第二名签字的载荷里必须包含第一名签字的摘要；
//     11. 两次签字间隔在策略内；
//     12. 审计链完整可校验，且两笔签字都出现在链里。
//
//   D. 时间
//     13. 时间证明中的 signedEpoch 必须落在锚记录允许的范围；
//        公司有自己签发锚的记录（anchorReceipts），可精确重算。
//     14. （可选）审计里存在 timeAnchored 事件。
//
// 输出：结构化的 AuditReport，给出每条结论而不是单一布尔值，
// 便于复核人员看到"为什么可信 / 哪里存疑"。

import Foundation
import EFBCore
import EFBIdentity
import EFBCryptography

public struct AuditFinding: Equatable, Sendable, Codable {
    public let code: String
    public let passed: Bool
    public let detail: String

    public init(code: String, passed: Bool, detail: String) {
        self.code = code
        self.passed = passed
        self.detail = detail
    }
}

public struct AuditReport: Equatable, Sendable, Codable {
    public let recordID: String
    public let findings: [AuditFinding]
    /// 冗余解释：所有检查都通过才为 true；同时 findings 里保留明细。
    public var passed: Bool { findings.allSatisfy(\.passed) }
    public var failures: [AuditFinding] { findings.filter { !$0.passed } }

    public init(recordID: String, findings: [AuditFinding]) {
        self.recordID = recordID
        self.findings = findings
    }
}

/// 公司签发时间锚时留下的回执。审计方可据此精确重算签字的真实时间。
public struct AnchorReceipt: Equatable, Sendable, Codable {
    public let deviceID: DeviceID
    public let authoritativeEpoch: Double
    public let validitySeconds: Double
    public let issuedAtEpoch: Double
    /// 锚定时的单调读数与本次开机身份。有了它，审计方可以**精确重算**
    /// 签字时刻是否为 anchored + (monotonicSigned - monotonicAnchor)，
    /// 而不是只检查落在某个 72 小时宽窗内。
    public let monotonicAtAnchor: Double
    public let bootIdentity: Double

    public init(
        deviceID: DeviceID,
        authoritativeEpoch: Double,
        validitySeconds: Double,
        issuedAtEpoch: Double,
        monotonicAtAnchor: Double = .nan,
        bootIdentity: Double = .nan
    ) {
        self.deviceID = deviceID
        self.authoritativeEpoch = authoritativeEpoch
        self.validitySeconds = validitySeconds
        self.issuedAtEpoch = issuedAtEpoch
        self.monotonicAtAnchor = monotonicAtAnchor
        self.bootIdentity = bootIdentity
    }

    public var hasMonotonicBaseline: Bool { !monotonicAtAnchor.isNaN && !bootIdentity.isNaN }
}

/// 公司侧持有的令牌签发清单（序列号 -> 签发详情）。
public struct IssuedTokenLedgerEntry: Equatable, Sendable, Codable {
    public let serial: TokenSerial
    public let flightID: FlightID
    public let crewID: CrewID
    public let seat: Seat
    public let deviceID: DeviceID
    public let purpose: ReleasePurpose
    public let issuedAtEpoch: Double

    public init(serial: TokenSerial, flightID: FlightID, crewID: CrewID, seat: Seat, deviceID: DeviceID, purpose: ReleasePurpose, issuedAtEpoch: Double) {
        self.serial = serial
        self.flightID = flightID
        self.crewID = crewID
        self.seat = seat
        self.deviceID = deviceID
        self.purpose = purpose
        self.issuedAtEpoch = issuedAtEpoch
    }
}

public struct IssuedCertificateRecord: Equatable, Sendable, Codable {
    public let certificate: CrewCertificate
    public let issuerID: String
    public let issuerPublicKeyX963: Data

    public init(certificate: CrewCertificate, issuerID: String, issuerPublicKeyX963: Data) {
        self.certificate = certificate
        self.issuerID = issuerID
        self.issuerPublicKeyX963 = issuerPublicKeyX963
    }
}

public struct ReleaseAuditContext: Sendable {
    public let anchor: TrustAnchor
    public let issuers: [IssuerRecord]
    /// 公司端保存的证书副本（用于核对设备上的证书是否真由公司签发，而非设备伪造）。
    public let issuedCertificates: [CertificateID: IssuedCertificateRecord]
    /// 公司端令牌签发清单。
    public let tokenLedger: [TokenSerial: IssuedTokenLedgerEntry]
    /// 已消耗 / 已作废的令牌。
    public let consumedTokens: Set<TokenSerial>
    /// 更晚期的撤销名单（离线设备可能还没同步到）。
    public let revokedCrew: Set<CrewID>
    public let revokedCertificates: Set<CertificateID>
    public let policy: CrewPolicy
    /// 锚回执（可空：若设备从未联网锚定，则只能信任其时间证明的自洽性）。
    public let anchorReceipts: [DeviceID: [AnchorReceipt]]

    public init(
        anchor: TrustAnchor,
        issuers: [IssuerRecord],
        issuedCertificates: [CertificateID: IssuedCertificateRecord],
        tokenLedger: [TokenSerial: IssuedTokenLedgerEntry],
        consumedTokens: Set<TokenSerial>,
        revokedCrew: Set<CrewID> = [],
        revokedCertificates: Set<CertificateID> = [],
        policy: CrewPolicy = .standard,
        anchorReceipts: [DeviceID: [AnchorReceipt]] = [:]
    ) {
        self.anchor = anchor
        self.issuers = issuers
        self.issuedCertificates = issuedCertificates
        self.tokenLedger = tokenLedger
        self.consumedTokens = consumedTokens
        self.revokedCrew = revokedCrew
        self.revokedCertificates = revokedCertificates
        self.policy = policy
        self.anchorReceipts = anchorReceipts
    }
}

public enum ReleaseAuditor {
    public static func audit(_ record: ReleaseRecord, context: ReleaseAuditContext) -> AuditReport {
        var findings: [AuditFinding] = []
        func add(_ code: String, _ passed: Bool, _ detail: String) {
            findings.append(AuditFinding(code: code, passed: passed, detail: detail))
        }

        // A. 证据完整性
        add("A1.signedPayloadReconstruct", verifyPayloadReconstruction(record), "逐字节重建被签载荷")
        add("A2.sealedDigest", verifySealedDigest(record), "签字摘要与内容一致")
        add("A3.signatureCrypto", verifyAllSignatures(record), "ECDSA 签名有效")
        add("A4.contentDigest", record.signatures.allSatisfy { $0.contentDigest == record.content.canonicalSHA256 }, "被签内容与记录一致")

        // B. 身份与授权
        let certFindings = verifyCertificates(record, context)
        findings.append(contentsOf: certFindings)
        let tokenFindings = verifyTokens(record, context)
        findings.append(contentsOf: tokenFindings)

        // C. 双人与互锁
        add("C0.signatureCount", verifySignatureCount(record, policy: context.policy), "签字人数符合策略")
        add("C1.distinctCrew", Set(record.signatures.map(\.crewID)).count == record.signatures.count, "两名不同机组")
        add("C2.seats", verifySeats(record), "左右座分别签字")
        add("C3.priorDigest", verifyPriorDigest(record), "第二名签字覆盖第一名摘要")
        add("C4.interval", verifyInterval(record, policy: context.policy), "双签间隔在策略内")
        add("C5.auditChain", record.auditLog.verify(), "审计散列链完整")
        add("C5b.releaseSignedEvents", verifyReleaseSignedEvents(record), "审计链含每位签字人的 releaseSigned 事件")
        add("C6.auditHeadMatch", verifyAuditHeads(record), "签字时的审计头与链一致")

        // D. 时间
        add("D1.timeAttestation", verifyTimeAttestation(record, context), "时间证明自洽")

        return AuditReport(recordID: record.recordID, findings: findings)
    }

    // MARK: A

    /// 逐字节重建被签载荷。
    ///
    /// 注意：不能假定"左座先签"。签署顺序由现场流程决定（机长或副驾驶都可能先签），
    /// 因此这里对"链式载荷指向另一位签字人"做**顺序无关**的校验：
    /// 双签时要求恰好一位签字人的载荷内嵌了另一位的摘要，且被引用的摘要确实来自对方。
    private static func verifyPayloadReconstruction(_ record: ReleaseRecord) -> Bool {
        let signatures = record.signatures
        var chainedCount = 0
        for signature in signatures {
            let base = plainPayload(record: record, signature: signature)
            if base.canonicalBytes == signature.signedPayloadBytes {
                continue
            }
            // 不是裸载荷，就必须是"链式"载荷，且引用的正是另一位签字人。
            guard signatures.count == 2,
                  let other = signatures.first(where: { $0.seat != signature.seat }),
                  let chained = chainedPayload(base: base, prior: other),
                  chained.canonicalBytes == signature.signedPayloadBytes else {
                return false
            }
            chainedCount += 1
        }
        // 双签必须恰好有一处链接，否则两名签字人互相独立、无法防止"先签后改"。
        if signatures.count == 2 {
            return chainedCount == 1
        }
        return signatures.count == 1
    }

    private static func plainPayload(record: ReleaseRecord, signature: PilotSignature) -> CanonicalValue {
        PilotSignature.buildSignedPayload(
            content: record.content,
            crew: signature.crewID,
            seat: signature.seat,
            tokenSerial: signature.tokenSerial,
            sessionID: signature.sessionID,
            signedAtEpoch: signature.signedAtEpoch,
            timeAttestation: signature.timeAttestation,
            auditHead: signature.auditHead,
            presenceFactor: signature.presenceFactor,
            certificateID: signature.certificateID,
            hardwareBacked: signature.hardwareBacked,
            keyProtection: signature.keyProtection
        )
    }

    private static func chainedPayload(base: CanonicalValue, prior: PilotSignature) -> CanonicalValue? {
        .object([
            "payload": base,
            "priorSignatureDigest": .string(SHA256Digest(hashing: prior).hexString),
        ])
    }

    private static func verifySealedDigest(_ record: ReleaseRecord) -> Bool {
        let recomputed = SHA256Digest(hashing: CanonicalValue.object([
            "auditHead": .string(record.auditLog.headHash.hexString),
            "content": .string(record.content.canonicalSHA256.hexString),
            "recordID": .string(record.recordID),
            "signatures": .array(record.signatures.map { .string(SHA256Digest(hashing: $0).hexString) }),
        ]))
        return recomputed == record.sealedDigest
    }

    private static func verifyAllSignatures(_ record: ReleaseRecord) -> Bool {
        record.signatures.allSatisfy { signature in
            SignatureVerifier.verify(
                signatureDER: signature.signatureDER,
                data: signature.signedPayloadBytes,
                publicKeyX963: signature.signingPublicKeyX963
            )
        }
    }

    // MARK: B

    private static func verifyCertificates(_ record: ReleaseRecord, _ context: ReleaseAuditContext) -> [AuditFinding] {
        var out: [AuditFinding] = []
        for signature in record.signatures {
            guard let issued = context.issuedCertificates[signature.certificateID] else {
                out.append(AuditFinding(code: "B1.certificateKnown", passed: false, detail: "公司没有签发过证书 \(signature.certificateID)"))
                continue
            }
            out.append(AuditFinding(code: "B1.certificateKnown", passed: true, detail: "证书 \(signature.certificateID) 在公司签发清单内"))

            let certificate = issued.certificate
            out.append(AuditFinding(
                code: "B2.certificateBinding",
                passed: certificate.crewID == signature.crewID &&
                        certificate.deviceID == record.deviceID &&
                        certificate.signingPublicKeyX963 == signature.signingPublicKeyX963,
                detail: "证书与签字人 / 设备 / 公钥绑定"
            ))
            out.append(AuditFinding(
                code: "B3.certificateTimeValid",
                passed: certificate.isTimeValid(at: signature.signedAtEpoch),
                detail: "签字时刻在证书有效期内"
            ))
            let issuer = context.issuers.first { $0.issuerID == issued.issuerID }
            let chainTrusted: Bool
            if let issuer {
                chainTrusted = issuer.verify(with: context.anchor, at: signature.signedAtEpoch)
                    && issuer.publicKeyX963 == issued.issuerPublicKeyX963
                    && certificate.anchorID == context.anchor.anchorID
            } else {
                chainTrusted = false
            }
            out.append(AuditFinding(code: "B4.chainToRoot", passed: chainTrusted, detail: "证书链到公司根 \(context.anchor.anchorID)"))
            out.append(AuditFinding(
                code: "B5.seatQualification",
                // 证书必须允许该座位；签字记录里的 role 是设备自报的，不能据此放宽
                //（否则伪造 role=instructor 就能绕过座位资格）。
                passed: certificate.covers(signature.seat),
                detail: "证书允许该座位"
            ))
            out.append(AuditFinding(
                code: "B6.notRevoked",
                passed: !context.revokedCrew.contains(signature.crewID) &&
                        !context.revokedCertificates.contains(signature.certificateID),
                detail: "机组与证书均未撤销"
            ))
        }
        return out
    }

    private static func verifyTokens(_ record: ReleaseRecord, _ context: ReleaseAuditContext) -> [AuditFinding] {
        var out: [AuditFinding] = []
        for signature in record.signatures {
            guard let ledger = context.tokenLedger[signature.tokenSerial] else {
                out.append(AuditFinding(code: "B7.tokenKnown", passed: false, detail: "序列号 \(signature.tokenSerial) 不在公司签发清单"))
                continue
            }
            out.append(AuditFinding(code: "B7.tokenKnown", passed: true, detail: "令牌 \(signature.tokenSerial) 由公司签发"))
            let bound = ledger.crewID == signature.crewID
                && ledger.flightID == record.flightID
                && ledger.seat == signature.seat
                && ledger.deviceID == record.deviceID
                && ledger.purpose == record.purpose
            out.append(AuditFinding(code: "B8.tokenBinding", passed: bound, detail: "令牌与机组 / 航班 / 座位 / 设备 / 用途一致"))
            out.append(AuditFinding(
                code: "B9.tokenConsumedOnce",
                passed: !context.consumedTokens.contains(signature.tokenSerial),
                detail: "该令牌此前未被使用"
            ))
        }
        // 两个签字不能用同一个令牌
        let serials = record.signatures.map(\.tokenSerial)
        out.append(AuditFinding(code: "B10.tokenUniqueness", passed: Set(serials).count == serials.count, detail: "签字使用互不相同的令牌"))
        return out
    }

    // MARK: C

    /// 每位签字人必须在审计链里留下一条 releaseSigned 事件，且其 crew/seat 与签字匹配。
    /// 这堵住了"删掉链尾 releaseSigned 事件、只留 tokenConsumed"的攻击。
    private static func verifyReleaseSignedEvents(_ record: ReleaseRecord) -> Bool {
        for signature in record.signatures {
            let found = record.auditLog.events.contains { event in
                event.kind == .releaseSigned && event.crew == signature.crewID && event.seat == signature.seat
            }
            if !found { return false }
        }
        return true
    }

    private static func verifySignatureCount(_ record: ReleaseRecord, policy: CrewPolicy) -> Bool {
        let expected = policy.requiresTwoPilotRelease ? 2 : 1
        return record.signatures.count == expected
    }

    private static func verifySeats(_ record: ReleaseRecord) -> Bool {
        guard record.signatures.count == 2 else { return record.signatures.count == 1 }
        let seats = Set(record.signatures.map(\.seat))
        return seats == [.left, .right]
    }

    private static func verifyPriorDigest(_ record: ReleaseRecord) -> Bool {
        // 与 A1 同源：只要双签里恰好有一人的载荷内嵌了对方的摘要即可（不假定左右顺序）。
        guard record.signatures.count == 2 else { return record.signatures.count == 1 }
        let chained = record.signatures.filter { signature in
            let base = plainPayload(record: record, signature: signature)
            guard let other = record.signatures.first(where: { $0.seat != signature.seat }),
                  let wrapped = chainedPayload(base: base, prior: other) else { return false }
            return wrapped.canonicalBytes == signature.signedPayloadBytes
        }
        return chained.count == 1
    }

    private static func verifyInterval(_ record: ReleaseRecord, policy: CrewPolicy) -> Bool {
        let epochs = record.signatures.map(\.signedAtEpoch)
        guard let minE = epochs.min(), let maxE = epochs.max() else { return false }
        return (maxE - minE) <= policy.maxIntervalBetweenSignaturesSeconds
    }

    private static func verifyAuditHeads(_ record: ReleaseRecord) -> Bool {
        // 签字记录里的 auditHead 必须是审计链中某个"链头"（某事件的 previousHash 或 hash）。
        let headsOfChain: [SHA256Digest] = record.auditLog.events.flatMap { [$0.previousHash, $0.hash] }
        let known = Set(headsOfChain)
        // 不接受 .zero 作为通配：那等于给伪造者一个免费通过的出口。
        return record.signatures.allSatisfy { signature in
            known.contains(signature.auditHead)
        }
    }

    // MARK: D

    private static func verifyTimeAttestation(_ record: ReleaseRecord, _ context: ReleaseAuditContext) -> Bool {
        // 第一步：时间证明必须自洽 —— signedEpoch 应能由单调读数差重算出来。
        // 这不能替代锚回执（单调读数本身也是设备自报），但它让"编造时间"变得
        // 必须连同单调读数一起编造，而单调读数又必须与锚的基准一致。
        for signature in record.signatures {
            let a = signature.timeAttestation
            let recomputed = a.recomputedSignedEpoch
            let tolerance = max(a.driftToleranceSeconds, 1)
            guard abs(recomputed - a.signedEpoch) <= tolerance else { return false }
            // signedEpoch 就是签字记录里的 signedAtEpoch（载荷已绑定），须一致。
            guard abs(a.signedEpoch - signature.signedAtEpoch) <= tolerance else { return false }
        }

        guard let receipts = context.anchorReceipts[record.deviceID], !receipts.isEmpty else {
            // 无锚回执时，只能验证自洽性（单调读数差与时间差一致）。
            return record.signatures.allSatisfy { signature in
                let attestation = signature.timeAttestation
                let expectedElapsed = attestation.signedEpoch - attestation.anchoredEpoch
                let tolerance = max(attestation.driftToleranceSeconds, 1)
                return expectedElapsed >= -tolerance
            }
        }
        // 有锚回执：优先用回执里的单调基线**精确重算**，而不是只检查落在宽窗内。
        return record.signatures.allSatisfy { signature in
            let attestation = signature.timeAttestation
            return receipts.contains { receipt in
                if receipt.hasMonotonicBaseline {
                    // 开机身份必须一致（防重启冻结）
                    guard abs(attestation.bootIdentity - receipt.bootIdentity) <= 1 else { return false }
                    let recomputed = receipt.authoritativeEpoch
                        + (attestation.monotonicAtSign - receipt.monotonicAtAnchor)
                    let tol = max(context.policy.clockDriftToleranceSeconds, attestation.driftToleranceSeconds)
                    // 重算值必须与声明值一致，且与锚基准相差的偏移量也必须一致
                    return abs(recomputed - attestation.signedEpoch) <= tol
                        && abs((attestation.anchoredEpoch - receipt.authoritativeEpoch)
                            - (attestation.monotonicAtAnchor - receipt.monotonicAtAnchor)) <= tol
                }
                let lower = receipt.authoritativeEpoch - context.policy.clockDriftToleranceSeconds
                let upper = receipt.authoritativeEpoch + receipt.validitySeconds + context.policy.clockDriftToleranceSeconds
                return attestation.anchoredEpoch >= lower && attestation.anchoredEpoch <= upper
                    && attestation.signedEpoch >= lower && attestation.signedEpoch <= upper
            }
        }
    }
}
