// SuitesFlow.swift
// 端到端流程：预置 → 登录 → 双人签字 → 公司离线核验 → 交接 → 篡改检测。

import Foundation
import EFBCore
import EFBCryptography
import EFBIdentity
import EFBRelease
import EFBSession
import EFBCompany
import EFBProvisioning

func runIdentityAndReleaseSuites(_ h: Harness) async {
    await h.asyncSuite("身份核验：解锁与签字授权") {
        let company = try! TestCompany(nowEpoch: now0)
        let device = try! TestDevice(deviceID: "IPAD-EFB-0123", nowEpoch: now0)
        let crew = try! Fixtures.crew("P0042")
        _ = try! Fixtures.enroll(crew: crew, seat: .left, role: .captain,
                                 pinDigits: "482913", device: device, company: company)

        let authenticator = device.authenticator(
            anchor: company.anchor, issuers: [company.issuerRecord], revocation: company.revocation
        )
        var audit = AuditLog()

        // 错误 PIN
        h.expectThrowsAny("错误 PIN 无法解锁") {
            _ = try authenticator.unlock(crew: crew, seat: .left, pin: SecureBytes(Array("482914".utf8)), audit: &audit)
        }
        // 正确 PIN
        let session = try! authenticator.unlock(crew: crew, seat: .left,
                                                pin: SecureBytes(Array("482913".utf8)), audit: &audit)
        h.expectEqual(session.crewID, crew, "解锁返回正确机组")
        h.expect(session.signingKey.isUnlocked, "签字密钥在会话开始时解开")

        // 现场核验失败 → 不签发 grant
        let gate = device.presence
        Task {
            await gate.script([.failed(reason: "Face ID 未通过")])
        }
        let grant: SignatureGrant? = try? await {
            return try await authenticator.authorizeSignature(for: session, scope: "release:R1", audit: &audit)
        }()
        h.expect(grant == nil, "现场核验失败则不签发授权")

        // 现场核验通过 → 签发一次性 grant
        Task {
            await gate.setDefault(.verified(factor: .biometric))
        }
        let okGrant = try! await authenticator.authorizeSignature(for: session, scope: "release:R1", audit: &audit)
        h.expectEqual(okGrant.maxUses, 1, "grant 默认只能使用一次")
        h.expectEqual(okGrant.presenceFactor, .biometric, "记录生物识别因素")

        var mutableGrant = okGrant
        h.expectNoThrow("首次消耗成功") {
            try authenticator.consume(&mutableGrant, session: session, scope: "release:R1", at: now0)
        }
        h.expectThrows(EFBError.grantExhausted, "第二次消耗失败") {
            try authenticator.consume(&mutableGrant, session: session, scope: "release:R1", at: now0)
        }
        h.expectThrowsAny("作用域不匹配被拒绝") {
            try authenticator.consume(&mutableGrant, session: session, scope: "release:R2", at: now0)
        }

        session.dispose()
        h.expect(session.isDisposed, "会话 dispose 后标记失效")
        // 已 dispose 的会话不能再获得新的签字授权
        var rejected = false
        do {
            _ = try await authenticator.authorizeSignature(for: session, scope: "release:R3", audit: &audit)
        } catch let error as EFBError {
            if case .sessionLocked = error { rejected = true }
        }
        h.expect(rejected, "失效会话不能再签发授权")
    }

    await h.asyncSuite("失败计数在成功解锁后仍被保留") {
        let company = try! TestCompany(nowEpoch: now0)
        let device = try! TestDevice(deviceID: "IPAD-EFB-0123", nowEpoch: now0)
        let crew = try! Fixtures.crew("P0042")
        _ = try! Fixtures.enroll(crew: crew, seat: .left, role: .captain,
                                 pinDigits: "482913", device: device, company: company)
        let auth = device.authenticator(anchor: company.anchor, issuers: [company.issuerRecord], revocation: company.revocation)
        var audit = AuditLog()
        // 先错 2 次
        for _ in 0..<2 {
            _ = try? auth.unlock(crew: crew, seat: .left, pin: SecureBytes(Array("000000".utf8)), audit: &audit)
        }
        // 再成功一次（应清零）
        _ = try! auth.unlock(crew: crew, seat: .left, pin: SecureBytes(Array("482913".utf8)), audit: &audit)
        // 再错 4 次不应被提前锁定到上限（若成功时把计数回滚，这里会提前锁）
        var lockedEarly = false
        for _ in 0..<4 {
            do {
                _ = try auth.unlock(crew: crew, seat: .left, pin: SecureBytes(Array("000000".utf8)), audit: &audit)
            } catch let error as EFBError {
                if case .pinLockedOut = error { lockedEarly = true }
            } catch {}
        }
        h.expect(!lockedEarly, "成功解锁已清零计数，不会提前锁定")
    }

    await h.asyncSuite("PIN 修改：旧 PIN 验证与历史查重") {
        let company = try! TestCompany(nowEpoch: now0)
        let device = try! TestDevice(deviceID: "IPAD-EFB-0123", nowEpoch: now0)
        let crew = try! Fixtures.crew("P0042")
        _ = try! Fixtures.enroll(crew: crew, seat: .left, role: .captain,
                                 pinDigits: "482913", device: device, company: company)

        h.expectThrowsAny("旧 PIN 错时不能改 PIN") {
            try PINManagement.changePIN(
                crew: crew, oldPIN: SecureBytes(Array("000000".utf8)),
                newPIN: SecureBytes(Array("594817".utf8)),
                store: device.credentialStore, policy: .standard, time: device.time
            )
        }
        h.expectThrowsAny("新 PIN 不能与历史重复") {
            try PINManagement.changePIN(
                crew: crew, oldPIN: SecureBytes(Array("482913".utf8)),
                newPIN: SecureBytes(Array("482913".utf8)),
                store: device.credentialStore, policy: .standard, time: device.time
            )
        }
        h.expectNoThrow("合法改 PIN 成功") {
            try PINManagement.changePIN(
                crew: crew, oldPIN: SecureBytes(Array("482913".utf8)),
                newPIN: SecureBytes(Array("594817".utf8)),
                store: device.credentialStore, policy: .standard, time: device.time
            )
        }
        let authenticator = device.authenticator(
            anchor: company.anchor, issuers: [company.issuerRecord], revocation: company.revocation
        )
        var audit = AuditLog()
        h.expectThrowsAny("旧 PIN 已失效") {
            _ = try authenticator.unlock(crew: crew, seat: .left,
                                         pin: SecureBytes(Array("482913".utf8)), audit: &audit)
        }
        h.expectNoThrow("新 PIN 解锁成功") {
            _ = try authenticator.unlock(crew: crew, seat: .left,
                                         pin: SecureBytes(Array("594817".utf8)), audit: &audit)
        }
    }

    await h.asyncSuite("双人共签 + 公司离线核验") {
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
            computedAtEpoch: now0, performanceInputDigest: SHA256Digest(hashing: Data("perf-input".utf8)),
            fuelKg: 9_800
        )

        let sessions = (try! authenticator.unlock(crew: captain, seat: .left,
                                                 pin: SecureBytes(Array("482913".utf8)), audit: &audit),
                        try! authenticator.unlock(crew: fO, seat: .right,
                                                 pin: SecureBytes(Array("731429".utf8)), audit: &audit))

        let recordID = "R-CA1831-TEST"

        // 机长签字
        let first = try! await signer.sign(
            session: sessions.0, content: content, purpose: .departure,
            recordID: recordID, existingSignatures: [], audit: &audit
        )
        h.expectEqual(first.seat, .left, "第一位签字为左座")
        h.expect(audit.verify(), "签字后审计链完整")

        // 副驾驶签字（互锁）
        let second = try! await signer.sign(
            session: sessions.1, content: content, purpose: .departure,
            recordID: recordID, existingSignatures: [first], audit: &audit
        )
        h.expectEqual(second.seat, .right, "第二位签字为右座")

        let record = try! signer.finalize(
            recordID: recordID, content: content, purpose: .departure,
            signatures: [first, second], audit: audit
        )
        h.expectEqual(record.signatures.count, 2, "记录含两名签字人")

        // 公司侧离线核验
        let report = ReleaseAuditor.audit(record, context: company.auditContext())
        h.expect(report.passed, "公司离线核验通过")
        if !report.passed {
            for failure in report.failures { print("    失败项：\(failure.code) — \(failure.detail)") }
        }
        h.expect(report.findings.count >= 18, "核验项完整（\(report.findings.count) 项）")

        // 同一人签两角被拒绝
        do {
            let again: PilotSignature = try await signer.sign(
                session: sessions.0, content: content, purpose: .departure,
                recordID: "R2", existingSignatures: [first], audit: &audit
            )
            h.expect(false, "同一人签两角应被拒绝（但得到 \(again.seat)）")
        } catch let error as EFBReleaseError {
            if case .duplicateSigner = error { h.expect(true, "同一人签两角被拒绝") }
            else { h.expect(false, "同一人签两角被拒绝（得到 \(error)）") }
        } catch {
            h.expect(false, "同一人签两角被拒绝（意外错误 \(error)）")
        }
    }
}

func runCockpitAppSuites(_ h: Harness) async {
    await h.asyncSuite("CockpitApp 全流程（bootstrap → 双签 → 归档 → 核验）") {
        let company = try! TestCompany(nowEpoch: now0)
        let deviceID = try! DeviceID(validating: "IPAD-EFB-0123")
        let store = InMemorySecureStore()
        let tokenStore = ReleaseTokenStore()
        let clock = ManualClock(uptimeSeconds: 100)
        let bootIdentity = clock.bootIdentity
        let anchor = TimeAnchor(authoritativeEpoch: now0, monotonicAtAnchor: 100, issuedAtEpoch: now0,
                                validitySeconds: 72 * 3600, driftToleranceSeconds: 60, bootIdentity: bootIdentity)
        let time = try! AnchoredTimeProvider(anchor: anchor, clock: clock)
        let presence = ScriptedPresenceGate()
        let app = CockpitApp(
            deviceID: deviceID, pinnedAnchor: company.anchor, tokenStore: tokenStore, timeProvider: time,
            clock: clock, store: store, keyVault: SoftwareKeyVault(), presence: presence
        )

        // 未预置：拒绝一切
        h.expectThrowsAny("未预置时无法登录") {
            _ = try app.signIn(crew: try! Fixtures.crew("P0042"), seat: .left,
                               pin: SecureBytes(Array("482913".utf8)))
        }

        // 装配两位机组（用 CockpitApp 的预置阶段 API）
        let captain = try! Fixtures.crew("P0042")
        let fO = try! Fixtures.crew("P0057")
        let capKey = try! app.prepareCrewKey(crew: captain, pin: SecureBytes(Array("482913".utf8)))
        let capCert = try! company.issueCertificate(crew: captain, seat: .left, role: .captain,
                                                    device: deviceID, publicKey: capKey.publicKeyX963)
        _ = try! app.enrollCrew(crew: captain, role: .captain, seats: [.left],
                                pin: SecureBytes(Array("482913".utf8)), certificate: capCert,
                                revocationEpoch: company.revocation.epoch, key: capKey)
        let foKey = try! app.prepareCrewKey(crew: fO, pin: SecureBytes(Array("731429".utf8)))
        let foCert = try! company.issueCertificate(crew: fO, seat: .right, role: .firstOfficer,
                                                   device: deviceID, publicKey: foKey.publicKeyX963)
        _ = try! app.enrollCrew(crew: fO, role: .firstOfficer, seats: [.right],
                                pin: SecureBytes(Array("731429".utf8)), certificate: foCert,
                                revocationEpoch: company.revocation.epoch, key: foKey)

        // 本场预置：锚 / 根 / 撤销名单 / 令牌
        let flight = try! Fixtures.flight("CA1831-2026-11-24")
        let tokens = try! company.issueTokens(
            flight: flight,
            assignments: [(captain, .left, deviceID), (fO, .right, deviceID)]
        )
        let package = try! company.authority.issueBootstrapPackage(
            deviceID: deviceID,
            timeAnchor: anchor,
            issuers: [company.issuerRecord],
            revocation: company.revocation, tokens: tokens, policy: .standard
        )
        try! app.bootstrap(package, nowEpoch: now0)

        let captainSession = try! app.signIn(crew: captain, seat: .left, pin: SecureBytes(Array("482913".utf8)))
        let foSession = try! app.signIn(crew: fO, seat: .right, pin: SecureBytes(Array("731429".utf8)))
        h.expectEqual(app.auditSnapshot.events.count > 0, true, "审计已写入")

        let content = ReleaseContent(
            flightID: flight, departure: "PEK", destination: "SHA", aircraftRegistration: "B-1234",
            takeoffWeightKg: 72_000, vSpeedsKt: [148, 152, 155], runway: "18L",
            computedAtEpoch: now0, performanceInputDigest: SHA256Digest(hashing: Data("perf".utf8)),
            fuelKg: 9_800
        )
        let recordID = "R-APP"
        let first = try! await app.signRelease(session: captainSession, content: content,
                                               purpose: .departure, recordID: recordID, existing: [])
        let second = try! await app.signRelease(session: foSession, content: content,
                                                purpose: .departure, recordID: recordID, existing: [first])
        let record = try! app.finalizeRelease(recordID: recordID, content: content,
                                              purpose: .departure, signatures: [first, second])
        let report = ReleaseAuditor.audit(record, context: company.auditContext())
        h.expect(report.passed, "CockpitApp 产生的记录通过公司核验")

        try! app.archiveRelease(record)
        h.expect(try! app.pendingRecords().count == 1, "待上传队列含 1 条")
        try! app.markRecordUploaded(recordID)
        h.expect(try! app.pendingRecords().isEmpty, "标记后清空")

        // 交接后旧会话无法再签字（座位校验接线生效）
        try! app.signOut(seat: .left)
        await h.expectThrowsAnyAsync("登出后旧句柄无法签字") {
            _ = try await app.signRelease(session: captainSession, content: content,
                                         purpose: .departure, recordID: "R-APP2", existing: [])
        }
    }
}

func runArchiveSuites(_ h: Harness) async {
    await h.asyncSuite("归档与上传队列") {
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
        let s1 = try! authenticator.unlock(crew: captain, seat: .left, pin: SecureBytes(Array("482913".utf8)), audit: &audit)
        let s2 = try! authenticator.unlock(crew: fO, seat: .right, pin: SecureBytes(Array("731429".utf8)), audit: &audit)
        let first = try! await signer.sign(session: s1, content: content, purpose: .departure,
                                           recordID: "R-ARCH", existingSignatures: [], audit: &audit)
        let second = try! await signer.sign(session: s2, content: content, purpose: .departure,
                                            recordID: "R-ARCH", existingSignatures: [first], audit: &audit)
        let record = try! signer.finalize(recordID: "R-ARCH", content: content, purpose: .departure,
                                          signatures: [first, second], audit: audit)

        let archive = ReleaseArchive(store: device.store)
        try! archive.archive(record)
        try! archive.archive(record) // 幂等
        h.expect(try! archive.allRecordIDs() == ["R-ARCH"], "归档幂等且只登记一次")
        h.expect(try! archive.pendingUpload().count == 1, "待上传队列含 1 条")
        try! archive.markUploaded("R-ARCH")
        h.expect(try! archive.pendingUpload().isEmpty, "标记上传后队列清空")
        // 归档的记录仍能被公司核验
        if let restored = try! archive.record("R-ARCH") {
            let report = ReleaseAuditor.audit(restored, context: company.auditContext())
            h.expect(report.passed, "归档后取回仍能通过离线核验")
        } else {
            h.expect(false, "归档后应能取回")
        }
    }

    await h.asyncSuite("预置包校验") {
        let company = try! TestCompany(nowEpoch: now0)
        let device = try! TestDevice(deviceID: "IPAD-EFB-0123", nowEpoch: now0)
        let flight = try! Fixtures.flight("CA1831-2026-11-24")
        let tokens = try! company.issueTokens(
            flight: flight,
            assignments: [(try! Fixtures.crew("P0042"), .left, device.deviceID)]
        )
        let anchor = TimeAnchor(authoritativeEpoch: now0, monotonicAtAnchor: 100, issuedAtEpoch: now0,
                                validitySeconds: 72 * 3600, driftToleranceSeconds: 60, bootIdentity: 1_700_000_000)
        let package = try! company.authority.issueBootstrapPackage(
            deviceID: device.deviceID, timeAnchor: anchor,
            issuers: [company.issuerRecord], revocation: company.revocation,
            tokens: tokens, policy: .standard
        )
        h.expectNoThrow("合法预置包通过校验") {
            try BootstrapValidator.validate(package, deviceID: device.deviceID, nowEpoch: now0,
                                           pinnedAnchor: company.anchor, pinRootPublicKey: company.anchor.publicKeyX963)
        }
        h.expectThrowsAny("设备号不符被拒绝") {
            try BootstrapValidator.validate(package, deviceID: try! DeviceID(validating: "IPAD-EFB-9999"), nowEpoch: now0,
                                           pinnedAnchor: company.anchor, pinRootPublicKey: company.anchor.publicKeyX963)
        }
        h.expectThrowsAny("包签名被换根伪造时拒绝") {
            try BootstrapValidator.validate(package, deviceID: device.deviceID, nowEpoch: now0,
                                           pinnedAnchor: company.anchor, pinRootPublicKey: SoftwareSigningKey().publicKeyX963)
        }
        // 锚的权威时间大幅超前
        let futureAnchor = TimeAnchor(authoritativeEpoch: now0 + 3 * 86400, monotonicAtAnchor: 100,
                                      issuedAtEpoch: now0 + 3 * 86400, validitySeconds: 72 * 3600,
                                      driftToleranceSeconds: 60, bootIdentity: 1_700_000_000)
        let futurePackage = try! company.authority.issueBootstrapPackage(
            deviceID: device.deviceID, timeAnchor: futureAnchor,
            issuers: [company.issuerRecord], revocation: company.revocation,
            tokens: tokens, policy: .standard
        )
        h.expectThrowsAny("锚时间大幅超前被拒绝") {
            try BootstrapValidator.validate(futurePackage, deviceID: device.deviceID, nowEpoch: now0,
                                           pinnedAnchor: company.anchor, pinRootPublicKey: company.anchor.publicKeyX963)
        }
        // 伪造撤销名单（用另一把私钥签）必须被拒
        let forgedRevocation = try! company.authority.issueRevocationSnapshot(
            epoch: 2, revokedCertificates: [], revokedCrew: [],
            issuerID: company.issuerID, issuerKey: SoftwareSigningKey()
        )
        let forgedPackage = try! company.authority.issueBootstrapPackage(
            deviceID: device.deviceID, timeAnchor: anchor,
            issuers: [company.issuerRecord], revocation: forgedRevocation,
            tokens: tokens, policy: .standard
        )
        h.expectThrowsAny("伪造撤销名单被拒") {
            try BootstrapValidator.validate(forgedPackage, deviceID: device.deviceID, nowEpoch: now0,
                                           pinnedAnchor: company.anchor, pinRootPublicKey: company.anchor.publicKeyX963)
        }
    }
}
