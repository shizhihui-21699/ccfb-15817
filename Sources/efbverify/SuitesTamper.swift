// SuitesTamper.swift
// 篡改检测：任何对记录、令牌、证书、审计链的改动都必须被公司侧核验拒绝。

import Foundation
import EFBCore
import EFBCryptography
import EFBIdentity
import EFBRelease
import EFBSession
import EFBCompany

func runTamperSuites(_ h: Harness) async {
    await h.asyncSuite("记录篡改检测") {
        let company = try! TestCompany(nowEpoch: now0)
        let device = try! TestDevice(deviceID: "IPAD-EFB-0123", nowEpoch: now0)
        let captain = try! Fixtures.crew("P0042")
        let fO = try! Fixtures.crew("P0057")
        _ = try! Fixtures.enroll(crew: captain, seat: .left, role: .captain,
                                 pinDigits: "482913", device: device, company: company)
        _ = try! Fixtures.enroll(crew: fO, seat: .right, role: .firstOfficer,
                                 pinDigits: "731429", device: device, company: company)

        let flight = try! Fixtures.flight("CA1831-2026-11-24")
        let tokens = try! company.issueTokens(
            flight: flight,
            assignments: [(captain, .left, device.deviceID), (fO, .right, device.deviceID)]
        )
        let tokenStore = ReleaseTokenStore()
        try! tokenStore.load(tokens)
        let authenticator = device.authenticator(
            anchor: company.anchor, issuers: [company.issuerRecord], revocation: company.revocation
        )
        let signer = ReleaseSigner(
            authenticator: authenticator, tokenStore: tokenStore,
            tokenVerifier: IssuerKeyTokenVerifier(trustedIssuerKeys: [company.issuerID: company.issuerKey.publicKeyX963]),
            policy: .standard, time: device.time, deviceID: device.deviceID
        )
        var audit = AuditLog()
        let content = ReleaseContent(
            flightID: flight, departure: "PEK", destination: "SHA", aircraftRegistration: "B-1234",
            takeoffWeightKg: 72_000, vSpeedsKt: [148, 152, 155], runway: "18L",
            computedAtEpoch: now0, performanceInputDigest: SHA256Digest(hashing: Data("perf".utf8)),
            fuelKg: 9_800
        )
        let s1 = try! authenticator.unlock(crew: captain, seat: .left,
                                           pin: SecureBytes(Array("482913".utf8)), audit: &audit)
        let s2 = try! authenticator.unlock(crew: fO, seat: .right,
                                            pin: SecureBytes(Array("731429".utf8)), audit: &audit)
        let first = try! await signer.sign(session: s1, content: content, purpose: .departure,
                                           recordID: "R-T", existingSignatures: [], audit: &audit)
        let second = try! await signer.sign(session: s2, content: content, purpose: .departure,
                                            recordID: "R-T", existingSignatures: [first], audit: &audit)
        let record = try! signer.finalize(recordID: "R-T", content: content, purpose: .departure,
                                          signatures: [first, second], audit: audit)
        h.expect(ReleaseAuditor.audit(record, context: company.auditContext()).passed, "原始记录通过核验")

        // 篡改 1：改起飞重量（内容与被签摘要不再对应）
        let tamperedContent = ReleaseContent(
            flightID: flight, departure: "PEK", destination: "SHA", aircraftRegistration: "B-1234",
            takeoffWeightKg: 75_000, vSpeedsKt: [148, 152, 155], runway: "18L",
            computedAtEpoch: now0, performanceInputDigest: SHA256Digest(hashing: Data("perf".utf8)),
            fuelKg: 9_800
        )
        let tamperedRecord = ReleaseRecord(
            recordID: record.recordID, flightID: record.flightID, content: tamperedContent,
            purpose: record.purpose, deviceID: record.deviceID, signatures: record.signatures,
            auditLog: record.auditLog, sealedDigest: record.sealedDigest
        )
        let report1 = ReleaseAuditor.audit(tamperedRecord, context: company.auditContext())
        h.expect(!report1.passed, "改起飞重量被发现")
        h.expect(report1.failures.contains { $0.code == "A4.contentDigest" }, "失败项包含内容摘要")

        // 篡改 2：把右座签字时间往前挪
        var sig = second
        sig = PilotSignature(
            crewID: sig.crewID, seat: sig.seat, role: sig.role, certificateID: sig.certificateID,
            signingPublicKeyX963: sig.signingPublicKeyX963, tokenSerial: sig.tokenSerial,
            sessionID: sig.sessionID, signedAtEpoch: sig.signedAtEpoch - 3000,
            timeAttestation: sig.timeAttestation, presenceFactor: sig.presenceFactor,
            hardwareBacked: sig.hardwareBacked, keyProtection: sig.keyProtection,
            unlockedAtEpoch: sig.unlockedAtEpoch, auditHead: sig.auditHead,
            contentDigest: sig.contentDigest, signatureDER: sig.signatureDER,
            signedPayloadBytes: sig.signedPayloadBytes
        )
        let record2 = ReleaseRecord(
            recordID: record.recordID, flightID: record.flightID, content: record.content,
            purpose: record.purpose, deviceID: record.deviceID, signatures: [first, sig],
            auditLog: record.auditLog, sealedDigest: record.sealedDigest
        )
        let report2 = ReleaseAuditor.audit(record2, context: company.auditContext())
        h.expect(!report2.passed, "改签字时间被发现")
        h.expect(report2.failures.contains { $0.code == "A1.signedPayloadReconstruct" || $0.code == "A3.signatureCrypto" },
                 "失败项包含载荷重建或签名")

        // 篡改 3：换掉右座证书标识（冒用身份）
        let record3 = ReleaseRecord(
            recordID: record.recordID, flightID: record.flightID, content: record.content,
            purpose: record.purpose, deviceID: record.deviceID,
            signatures: [first, PilotSignature(
                crewID: captain, seat: .right, role: .firstOfficer, certificateID: first.certificateID,
                signingPublicKeyX963: second.signingPublicKeyX963, tokenSerial: second.tokenSerial,
                sessionID: second.sessionID, signedAtEpoch: second.signedAtEpoch,
                timeAttestation: second.timeAttestation, presenceFactor: second.presenceFactor,
                hardwareBacked: second.hardwareBacked, keyProtection: second.keyProtection,
                unlockedAtEpoch: second.unlockedAtEpoch, auditHead: second.auditHead,
                contentDigest: second.contentDigest, signatureDER: second.signatureDER,
                signedPayloadBytes: second.signedPayloadBytes
            )],
            auditLog: record.auditLog, sealedDigest: record.sealedDigest
        )
        let report3 = ReleaseAuditor.audit(record3, context: company.auditContext())
        h.expect(!report3.passed, "冒用身份被发现")
        h.expect(report3.failures.contains { $0.code == "C1.distinctCrew" }, "失败项包含同一人签两角")

        // 篡改 4：审计链删除一条
        var events = record.auditLog.events
        events.remove(at: 1)
        let record4 = ReleaseRecord(
            recordID: record.recordID, flightID: record.flightID, content: record.content,
            purpose: record.purpose, deviceID: record.deviceID, signatures: record.signatures,
            auditLog: AuditLog(events: events), sealedDigest: record.sealedDigest
        )
        let report4 = ReleaseAuditor.audit(record4, context: company.auditContext())
        h.expect(!report4.passed, "删审计事件被发现")
        h.expect(report4.failures.contains { $0.code == "C5.auditChain" }, "失败项包含审计链")

        // 篡改 4.5：只删链尾（保留签名时的链头），必须被发现
        var tailEvents = record.auditLog.events
        if tailEvents.count > 1 { tailEvents.removeLast() }
        let recordTail = ReleaseRecord(
            recordID: record.recordID, flightID: record.flightID, content: record.content,
            purpose: record.purpose, deviceID: record.deviceID, signatures: record.signatures,
            auditLog: AuditLog(events: tailEvents), sealedDigest: record.sealedDigest
        )
        let reportTail = ReleaseAuditor.audit(recordTail, context: company.auditContext())
        h.expect(!reportTail.passed, "删链尾事件被发现")
        h.expect(reportTail.failures.contains { $0.code == "A2.sealedDigest" },
                 "失败项包含封存摘要（链尾已进摘要）")

        // 篡改 4.6：只留到 tokenConsumed 事件（签名时的链头），删掉 releaseSigned 尾事件
        // 构造：截断到第一处 tokenConsumed 之后
        var truncated = record.auditLog.events
        if let idx = truncated.firstIndex(where: { $0.kind == .tokenConsumed }) {
            truncated = Array(truncated.prefix(idx + 1))
        }
        let recordNoSigned = ReleaseRecord(
            recordID: record.recordID, flightID: record.flightID, content: record.content,
            purpose: record.purpose, deviceID: record.deviceID, signatures: record.signatures,
            auditLog: AuditLog(events: truncated), sealedDigest: record.sealedDigest
        )
        let reportNoSigned = ReleaseAuditor.audit(recordNoSigned, context: company.auditContext())
        h.expect(!reportNoSigned.passed, "删掉 releaseSigned 尾事件被发现")

        // 篡改 5：令牌序列号不在公司清单
        let bogusSignature = PilotSignature(
            crewID: second.crewID, seat: second.seat, role: second.role,
            certificateID: second.certificateID, signingPublicKeyX963: second.signingPublicKeyX963,
            tokenSerial: try! TokenSerial(validating: "TK-FAKE-999"),
            sessionID: second.sessionID, signedAtEpoch: second.signedAtEpoch,
            timeAttestation: second.timeAttestation, presenceFactor: second.presenceFactor,
            hardwareBacked: second.hardwareBacked, keyProtection: second.keyProtection,
            unlockedAtEpoch: second.unlockedAtEpoch, auditHead: second.auditHead,
            contentDigest: second.contentDigest, signatureDER: second.signatureDER,
            signedPayloadBytes: second.signedPayloadBytes
        )
        let record5 = ReleaseRecord(
            recordID: record.recordID, flightID: record.flightID, content: record.content,
            purpose: record.purpose, deviceID: record.deviceID, signatures: [first, bogusSignature],
            auditLog: record.auditLog, sealedDigest: record.sealedDigest
        )
        let report5 = ReleaseAuditor.audit(record5, context: company.auditContext())
        h.expect(!report5.passed, "未知令牌被发现")
        h.expect(report5.failures.contains { $0.code == "B7.tokenKnown" }, "失败项包含令牌未知")
    }

    h.suite("令牌一次性与吊销") {
        let company = try! TestCompany(nowEpoch: now0)
        let device = try! TestDevice(deviceID: "IPAD-EFB-0123", nowEpoch: now0)
        let captain = try! Fixtures.crew("P0042")
        _ = try! Fixtures.enroll(crew: captain, seat: .left, role: .captain,
                                 pinDigits: "482913", device: device, company: company)
        let flight = try! Fixtures.flight("CA1831-2026-11-24")
        let tokens = try! company.issueTokens(flight: flight,
                                              assignments: [(captain, .left, device.deviceID)])
        let store = ReleaseTokenStore()
        try! store.load(tokens)
        let serial = tokens[0].serial

        h.expectNoThrow("首次消耗成功") { _ = try store.consume(serial, at: now0) }
        h.expectThrows(EFBError.tokenAlreadyConsumed(serial: serial), "重复消耗被拒绝") {
            _ = try store.consume(serial, at: now0)
        }

        // 某些情况：公司已经吊销该机组
        let revoked = try! company.authority.issueRevocationSnapshot(
            epoch: 1, revokedCertificates: [], revokedCrew: [captain],
            issuerID: company.issuerID, issuerKey: company.issuerKey
        )
        let revokedDevice = try! TestDevice(deviceID: "IPAD-EFB-0123", nowEpoch: now0)
        let revokedAuth = revokedDevice.authenticator(
            anchor: company.anchor, issuers: [company.issuerRecord], revocation: revoked
        )
        var audit = AuditLog()
        h.expectThrows(EFBError.credentialMissing(crew: captain), "吊销设备上未预置该机组") {
            _ = try revokedAuth.unlock(crew: captain, seat: .left, pin: SecureBytes(Array("000000".utf8)), audit: &audit)
        }
    }

    h.suite("证书过期与设备不符") {
        let company = try! TestCompany(nowEpoch: now0)
        let device = try! TestDevice(deviceID: "IPAD-EFB-0123", nowEpoch: now0)
        let crew = try! Fixtures.crew("P0042")
        _ = try! Fixtures.enroll(crew: crew, seat: .left, role: .captain,
                                 pinDigits: "482913", device: device, company: company)
        var audit = AuditLog()
        // 把时间推过证书有效期（证书 20 年，锚只允许 72 小时，所以先换时间源）
        let farFuture: TrustedTimeProviding = FixedTimeProvider(epoch: now0 + 21 * 365 * 86400)
        let authFuture = CrewAuthenticator(
            store: device.credentialStore, deviceID: device.deviceID,
            policy: .standard, time: farFuture, presence: device.presence,
            keyVault: device.keyVault, anchor: company.anchor,
            issuerRecords: [company.issuerRecord], revocation: company.revocation
        )
        h.expectThrows(EFBError.credentialExpired, "过期证书无法解锁") {
            _ = try authFuture.unlock(crew: crew, seat: .left, pin: SecureBytes(Array("482913".utf8)), audit: &audit)
        }

        // 设备不符：证书绑定的设备是 IPAD-EFB-0123，但当前是另一台
        let otherDevice = try! TestDevice(deviceID: "IPAD-EFB-0456", nowEpoch: now0)
        // 把凭据记录拷到另一台设备（模拟整机拷走）
        try! otherDevice.credentialStore.save(try! device.credentialStore.load(crew)!)
        let authOther = otherDevice.authenticator(
            anchor: company.anchor, issuers: [company.issuerRecord], revocation: company.revocation
        )
        h.expectThrows(EFBError.credentialDeviceMismatch(crew: crew, expected: otherDevice.deviceID, actual: device.deviceID),
                       "凭据被拷到另一台设备会因设备绑定被拒") {
            _ = try authOther.unlock(crew: crew, seat: .left, pin: SecureBytes(Array("482913".utf8)), audit: &audit)
        }
    }
}
