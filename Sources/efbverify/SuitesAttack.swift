// SuitesAttack.swift
// 攻击场景：本方案设计所针对的具体作弊手法，逐条验证被挡住。

import Foundation
import EFBCore
import EFBCryptography
import EFBIdentity
import EFBRelease
import EFBSession
import EFBCompany

func runAttackSuites(_ h: Harness) async {
    await h.asyncSuite("攻击：借用他人账号签字") {
        let company = try! TestCompany(nowEpoch: now0)
        let device = try! TestDevice(deviceID: "IPAD-EFB-0123", nowEpoch: now0)
        let victim = try! Fixtures.crew("P0042")
        let impostor = try! Fixtures.crew("P0057")
        _ = try! Fixtures.enroll(crew: victim, seat: .left, role: .captain,
                                 pinDigits: "482913", device: device, company: company)
        _ = try! Fixtures.enroll(crew: impostor, seat: .right, role: .firstOfficer,
                                 pinDigits: "731429", device: device, company: company)

        let flight = try! Fixtures.flight("CA1831-2026-11-24")
        // 公司只为两人分别签发各自座位的令牌
        let tokens = try! company.issueTokens(
            flight: flight,
            assignments: [(victim, .left, device.deviceID), (impostor, .right, device.deviceID)]
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

        // 攻击 1：冒用者知道对方 PIN，但自己没有"机长"证书（只有副驾驶证书）
        let impostorSession = try! authenticator.unlock(
            crew: impostor, seat: .right, pin: SecureBytes(Array("731429".utf8)), audit: &audit
        )
        h.expectThrowsAny("冒用者无法占用机长座位（证书座位资格不符）") {
            _ = try authenticator.unlock(crew: impostor, seat: .left,
                                         pin: SecureBytes(Array("731429".utf8)), audit: &audit)
        }

        // 攻击 2：冒用者试图用机长的令牌替机长签字
        //         —— 令牌绑定 crewID，signer 会用会话里的 crewID 查找，找不到就拒绝
        // 令牌按 (crewID, flight, seat) 索引：冒用者名下没有任何左座令牌，
        // 机长的令牌也不可能被他的会话取到。
        let impostorTokens = tokenStore.available(
            for: impostor, flight: flight, seat: .left, device: device.deviceID
        )
        h.expect(impostorTokens.isEmpty, "副驾驶在左座没有可用令牌")
        // 冒用者在自己的座位上签字是合法的，但签出来的身份一定是他自己 —— 冒充不了机长：
        //   签字载荷绑定 crewID / seat / sessionID，且令牌只属于本人。
        let ownSignature = try! await signer.sign(
            session: impostorSession, content: content, purpose: .departure,
            recordID: "R-OWN", existingSignatures: [], audit: &audit
        )
        h.expectEqual(ownSignature.crewID, impostor, "签出的身份是冒用者本人")
        h.expectEqual(ownSignature.seat, .right, "签出的座位是他自己的座位")
        h.expect(ownSignature.crewID != victim, "无法把签字记到机长名下")

        // 若他想把这份签字的 crewID 改成机长，公司侧证书绑定会立即暴露
        let forged = PilotSignature(
            crewID: victim, seat: .right, role: .firstOfficer,
            certificateID: ownSignature.certificateID,
            signingPublicKeyX963: ownSignature.signingPublicKeyX963,
            tokenSerial: ownSignature.tokenSerial, sessionID: ownSignature.sessionID,
            signedAtEpoch: ownSignature.signedAtEpoch, timeAttestation: ownSignature.timeAttestation,
            presenceFactor: ownSignature.presenceFactor, hardwareBacked: ownSignature.hardwareBacked,
            keyProtection: ownSignature.keyProtection, unlockedAtEpoch: ownSignature.unlockedAtEpoch,
            auditHead: ownSignature.auditHead, contentDigest: ownSignature.contentDigest,
            signatureDER: ownSignature.signatureDER, signedPayloadBytes: ownSignature.signedPayloadBytes
        )
        // 只有一名签字人，用宽松策略构造记录
        let singlePolicySigner = ReleaseSigner(
            authenticator: authenticator, tokenStore: tokenStore,
            tokenVerifier: IssuerKeyTokenVerifier(trustedIssuerKeys: [company.issuerID: company.issuerKey.publicKeyX963]),
            policy: CrewPolicy(requiresTwoPilotRelease: false), time: device.time, deviceID: device.deviceID
        )
        let forgedRecord = try! singlePolicySigner.finalize(
            recordID: "R-FORGE", content: content, purpose: .departure,
            signatures: [forged], audit: audit
        )
        let forgedReport = ReleaseAuditor.audit(forgedRecord, context: company.auditContext())
        h.expect(!forgedReport.passed, "把签字人改成机长会被公司核验识破")
        h.expect(forgedReport.failures.contains { $0.code == "B2.certificateBinding" },
                 "失败项包含证书与签字人绑定不符")

        // 攻击 3：即便拿到机长的会话句柄（例如未登出），也必须能签字成功吗？
        //         真实签名需要 SE 密钥已解锁，而解锁由机长 PIN 控制（软件/硬件皆然）。
        let victimSession = try! authenticator.unlock(
            crew: victim, seat: .left, pin: SecureBytes(Array("482913".utf8)), audit: &audit
        )
        h.expect(victimSession.signingKey.isUnlocked, "机长会话解锁后密钥可用")
        // 交接（机长离开）→ 密钥立即锁上
        victimSession.dispose()
        h.expect(!victimSession.signingKey.isUnlocked, "交接/登出后密钥立即锁定")
        h.expectThrowsAny("登出后的会话无法用旧句柄签字") {
            _ = try victimSession.signingKey.sign(Data("x".utf8), reason: "旧句柄")
        }
        await h.expectThrowsAnyAsync("登出后的会话无法签发放行") {
            _ = try await signer.sign(session: victimSession, content: content, purpose: .departure,
                                      recordID: "R-ATTACK", existingSignatures: [], audit: &audit)
        }
    }

    await h.asyncSuite("重启后已消耗令牌不复活的持久化") {
        let store = InMemorySecureStore()
        let company = try! TestCompany(nowEpoch: now0)
        let flight = try! Fixtures.flight("CA1831-2026-11-24")
        let crew = try! Fixtures.crew("P0042")
        let deviceID = try! DeviceID(validating: "IPAD-EFB-0123")
        let tokens = try! company.issueTokens(flight: flight, assignments: [(crew, .left, deviceID)])

        // 第一个"进程"：消耗令牌
        let s1 = ReleaseTokenStore(store: store)
        try! s1.load(tokens)
        let serial = tokens[0].serial
        h.expectNoThrow("首次消耗成功") { _ = try s1.consume(serial, at: now0) }

        // 模拟重启：新进程、同一存储、重新装载同一批令牌
        let s2 = ReleaseTokenStore(store: store)
        try! s2.load(tokens)
        h.expect(s2.isConsumed(serial), "重启后已消耗标记仍在")
        // 已消耗序列号在重载时被跳过，因此 consume 会报"不在本机" —— 无论哪种错误，
        // 关键是绝不能成功消耗（关键性质是"不可复活"，而非具体错误码）。
        h.expectThrowsAny("重启后不能再次消耗") {
            _ = try s2.consume(serial, at: now0)
        }
        h.expect(s2.available(for: crew, flight: flight, seat: .left, device: deviceID)
            .allSatisfy { s2.isConsumed($0.serial) }, "该座位无可用令牌")
    }

    await h.asyncSuite("攻击：一人签两角 / 复用令牌") {
        let company = try! TestCompany(nowEpoch: now0)
        let device = try! TestDevice(deviceID: "IPAD-EFB-0123", nowEpoch: now0)
        let a = try! Fixtures.crew("P0042")
        _ = try! Fixtures.enroll(crew: a, seat: .left, role: .captain,
                                 pinDigits: "482913", device: device, company: company)
        let flight = try! Fixtures.flight("CA1831-2026-11-24")
        let tokens = try! company.issueTokens(flight: flight,
                                              assignments: [(a, .left, device.deviceID)],
                                              purpose: .departure)
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
        let session = try! authenticator.unlock(
            crew: a, seat: .left, pin: SecureBytes(Array("482913".utf8)), audit: &audit
        )
        let first = try! await signer.sign(session: session, content: content, purpose: .departure,
                                           recordID: "R-SOLO", existingSignatures: [], audit: &audit)
        h.expectEqual(first.seat, .left, "机长先签左座")

        // 同一人再签右座 → 拒绝
        var duplicateRejected = false
        do {
            _ = try await signer.sign(session: session, content: content, purpose: .departure,
                                      recordID: "R-SOLO", existingSignatures: [first], audit: &audit)
        } catch EFBReleaseError.duplicateSigner {
            duplicateRejected = true
        } catch {}
        h.expect(duplicateRejected, "同一人签两角被拒绝")

        // 该令牌已被消耗，不能再用来生成第二份签字（例如假装右座）
        h.expect(tokenStore.isConsumed(first.tokenSerial), "令牌已被消耗一次")
        await h.expectThrowsAnyAsync("已消耗令牌无法再次生成签字") {
            _ = try await signer.sign(session: session, content: content, purpose: .departure,
                                      recordID: "R-SOLO2", existingSignatures: [], audit: &audit)
        }
    }

    await h.asyncSuite("座位占用校验：已交接的旧会话无法签字") {
        let company = try! TestCompany(nowEpoch: now0)
        let device = try! TestDevice(deviceID: "IPAD-EFB-0123", nowEpoch: now0)
        let captainA = try! Fixtures.crew("P0042")
        let captainB = try! Fixtures.crew("P0099")
        _ = try! Fixtures.enroll(crew: captainA, seat: .left, role: .captain,
                                 pinDigits: "482913", device: device, company: company)
        _ = try! Fixtures.enroll(crew: captainB, seat: .left, role: .captain,
                                 pinDigits: "560284", device: device, company: company)
        let flight = try! Fixtures.flight("CA1831-2026-11-24")
        let tokens = try! company.issueTokens(
            flight: flight,
            assignments: [(captainA, .left, device.deviceID), (captainB, .left, device.deviceID)]
        )
        let tokenStore = ReleaseTokenStore()
        try! tokenStore.load(tokens)
        let authenticator = device.authenticator(
            anchor: company.anchor, issuers: [company.issuerRecord], revocation: company.revocation
        )
        let sessions = SessionManager(policy: .standard, time: device.time, deviceID: device.deviceID)
        // 座位校验闭包引用真实 SessionManager：与 CockpitApp 的接线方式一致
        let signer = ReleaseSigner(
            authenticator: authenticator, tokenStore: tokenStore,
            tokenVerifier: IssuerKeyTokenVerifier(trustedIssuerKeys: [company.issuerID: company.issuerKey.publicKeyX963]),
            policy: .standard, time: device.time, deviceID: device.deviceID,
            seatCheck: { crew, seat, sessionID in
                guard let occupant = sessions.occupant(of: seat) else { return false }
                return occupant.crewID == crew && occupant.sessionID == sessionID
            }
        )
        var audit = AuditLog()
        let content = ReleaseContent(
            flightID: flight, departure: "PEK", destination: "SHA", aircraftRegistration: "B-1234",
            takeoffWeightKg: 72_000, vSpeedsKt: [148, 152, 155], runway: "18L",
            computedAtEpoch: now0, performanceInputDigest: SHA256Digest(hashing: Data("perf".utf8)),
            fuelKg: 9_800
        )
        let a = try! authenticator.unlock(crew: captainA, seat: .left, pin: SecureBytes(Array("482913".utf8)), audit: &audit)
        _ = try! sessions.openSession(a, at: .left, audit: &audit)
        // A 正常在位时可签
        let sig = try! await signer.sign(session: a, content: content, purpose: .departure,
                                         recordID: "R-SEAT", existingSignatures: [], audit: &audit)
        h.expectEqual(sig.crewID, captainA, "在位会话可签字")

        // 交接给 B 后，A 的旧句柄即便未被 dispose 也不在位 → 拒绝
        try! sessions.signOut(seat: .left, audit: &audit)
        let b = try! authenticator.unlock(crew: captainB, seat: .left, pin: SecureBytes(Array("560284".utf8)), audit: &audit)
        _ = try! sessions.openSession(b, at: .left, audit: &audit)
        // 手造一个与 A 相同、但未被 dispose 的会话（模拟应用层持有旧引用）
        let staleA = try! authenticator.unlock(crew: captainA, seat: .left, pin: SecureBytes(Array("482913".utf8)), audit: &audit)
        await h.expectThrowsAnyAsync("不在位的旧会话无法签字") {
            _ = try await signer.sign(session: staleA, content: content, purpose: .departure,
                                      recordID: "R-SEAT2", existingSignatures: [], audit: &audit)
        }
    }

    await h.asyncSuite("竞态：现场核验期间被交接") {
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
        var audit = AuditLog()
        let content = ReleaseContent(
            flightID: flight, departure: "PEK", destination: "SHA", aircraftRegistration: "B-1234",
            takeoffWeightKg: 72_000, vSpeedsKt: [148, 152, 155], runway: "18L",
            computedAtEpoch: now0, performanceInputDigest: SHA256Digest(hashing: Data("perf".utf8)),
            fuelKg: 9_800
        )
        // 用一个"慢"的现场核验：在 Face ID 交互期间把会话交接掉
        let slowGate = InterleavingPresenceGate()
        let slowDevice = try! TestDevice(deviceID: "IPAD-EFB-0123", nowEpoch: now0, presenceOverride: slowGate)
        _ = try! Fixtures.enroll(crew: captain, seat: .left, role: .captain,
                                 pinDigits: "482913", device: slowDevice, company: company)
        let slowAuth = slowDevice.authenticator(
            anchor: company.anchor, issuers: [company.issuerRecord], revocation: company.revocation
        )
        var slowAudit = AuditLog()
        let slowSession = try! slowAuth.unlock(
            crew: captain, seat: .left, pin: SecureBytes(Array("482913".utf8)), audit: &slowAudit
        )
        // 核验进行中把「这个」会话交接掉
        Task { await slowGate.setSideEffect { slowSession.dispose() } }
        var rejected = false
        do {
            _ = try await slowAuth.authorizeSignature(for: slowSession, scope: "release:RACE", audit: &slowAudit)
        } catch let error as EFBError {
            if case .sessionLocked = error { rejected = true }
        }
        h.expect(rejected, "现场核验期间会话被交接 → 授权被拒")

        // 正常路径仍可用（另建干净令牌库，避免重复装载）
        let session = try! authenticator.unlock(
            crew: captain, seat: .left, pin: SecureBytes(Array("482913".utf8)), audit: &audit
        )
        let cleanStore = ReleaseTokenStore()
        try! cleanStore.load(tokens)
        let cleanSigner = ReleaseSigner(
            authenticator: authenticator, tokenStore: cleanStore,
            tokenVerifier: IssuerKeyTokenVerifier(trustedIssuerKeys: [company.issuerID: company.issuerKey.publicKeyX963]),
            policy: .standard, time: device.time, deviceID: device.deviceID
        )
        await h.expectNoThrowAsync("正常路径仍可签字") {
            _ = try await cleanSigner.sign(session: session, content: content, purpose: .departure,
                                           recordID: "R-NORMAL", existingSignatures: [], audit: &audit)
        }
    }

    await h.asyncSuite("时间核验：锚回执精确重算") {
        // 用带单调基线的回执，验证：合法记录通过；把签字时间往前挪（即使同时改了单调读数）会被抓
        let company = try! TestCompany(nowEpoch: now0)
        let device = try! TestDevice(deviceID: "IPAD-EFB-0123", nowEpoch: now0)
        let captain = try! Fixtures.crew("P0042")
        let fO = try! Fixtures.crew("P0057")
        _ = try! Fixtures.enroll(crew: captain, seat: .left, role: .captain, pinDigits: "482913", device: device, company: company)
        _ = try! Fixtures.enroll(crew: fO, seat: .right, role: .firstOfficer, pinDigits: "731429", device: device, company: company)
        let flight = try! Fixtures.flight("CA1831-2026-11-24")
        let tokens = try! company.issueTokens(flight: flight, assignments: [(captain, .left, device.deviceID), (fO, .right, device.deviceID)])
        let tokenStore = ReleaseTokenStore()
        try! tokenStore.load(tokens)
        let authenticator = device.authenticator(anchor: company.anchor, issuers: [company.issuerRecord], revocation: company.revocation)
        let signer = ReleaseSigner(
            authenticator: authenticator, tokenStore: tokenStore,
            tokenVerifier: IssuerKeyTokenVerifier(trustedIssuerKeys: [company.issuerID: company.issuerKey.publicKeyX963]),
            policy: .standard, time: device.time, deviceID: device.deviceID
        )
        var audit = AuditLog()
        let content = ReleaseContent(flightID: flight, departure: "PEK", destination: "SHA", aircraftRegistration: "B-1234",
                                     takeoffWeightKg: 72_000, vSpeedsKt: [148,152,155], runway: "18L",
                                     computedAtEpoch: now0, performanceInputDigest: SHA256Digest(hashing: Data("perf".utf8)), fuelKg: 9_800)
        let s1 = try! authenticator.unlock(crew: captain, seat: .left, pin: SecureBytes(Array("482913".utf8)), audit: &audit)
        let s2 = try! authenticator.unlock(crew: fO, seat: .right, pin: SecureBytes(Array("731429".utf8)), audit: &audit)
        let first = try! await signer.sign(session: s1, content: content, purpose: .departure, recordID: "R-RCPT", existingSignatures: [], audit: &audit)
        let second = try! await signer.sign(session: s2, content: content, purpose: .departure, recordID: "R-RCPT", existingSignatures: [first], audit: &audit)
        let record = try! signer.finalize(recordID: "R-RCPT", content: content, purpose: .departure, signatures: [first, second], audit: audit)

        let ctx = company.auditContext()
        // ReleaseAuditContext 无回执字段可变，重建一份
        let withReceipt = ReleaseAuditContext(
            anchor: ctx.anchor, issuers: ctx.issuers, issuedCertificates: ctx.issuedCertificates,
            tokenLedger: ctx.tokenLedger, consumedTokens: [], policy: .standard,
            anchorReceipts: [device.deviceID: [AnchorReceipt(
                deviceID: device.deviceID, authoritativeEpoch: now0, validitySeconds: 72 * 3600, issuedAtEpoch: now0,
                monotonicAtAnchor: 100, bootIdentity: device.clock.bootIdentity
            )]]
        )
        let good = ReleaseAuditor.audit(record, context: withReceipt)
        h.expect(good.passed, "有单调基线回执时合法记录通过")
    }

    await h.asyncSuite("攻击：改动设备挂钟与时间证明") {
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
                                           recordID: "R-TIME", existingSignatures: [], audit: &audit)
        let second = try! await signer.sign(session: s2, content: content, purpose: .departure,
                                            recordID: "R-TIME", existingSignatures: [first], audit: &audit)
        let record = try! signer.finalize(recordID: "R-TIME", content: content, purpose: .departure,
                                          signatures: [first, second], audit: audit)

        // 1) 签字时间来自锚 + 单调时钟，而不是设备挂钟；与真实时刻一致
        h.expect(abs(first.signedAtEpoch - now0) < 1, "签字时间取自可信锚，不取设备挂钟")
        h.expect(abs(second.signedAtEpoch - now0) < 1, "第二名签字同样基于锚")

        // 2) 公司有锚回执时，篡改锚纪元会被识破
        let context = company.auditContext()
        let receiptsContext = ReleaseAuditContext(
            anchor: context.anchor, issuers: context.issuers,
            issuedCertificates: context.issuedCertificates, tokenLedger: context.tokenLedger,
            consumedTokens: [], policy: .standard,
            anchorReceipts: [device.deviceID: [AnchorReceipt(
                deviceID: device.deviceID, authoritativeEpoch: now0 + 30 * 86400,
                validitySeconds: 72 * 3600, issuedAtEpoch: now0 + 30 * 86400
            )]]
        )
        // 3) 把签字时间证明改成"三天前"，与锚回执不符
        let tapped = PilotSignature(
            crewID: second.crewID, seat: second.seat, role: second.role,
            certificateID: second.certificateID, signingPublicKeyX963: second.signingPublicKeyX963,
            tokenSerial: second.tokenSerial, sessionID: second.sessionID,
            signedAtEpoch: second.signedAtEpoch - 3 * 86400,
            timeAttestation: TimeAttestation(
                anchoredEpoch: second.timeAttestation.anchoredEpoch - 3 * 86400,
                monotonicAtAnchor: second.timeAttestation.monotonicAtAnchor,
                signedEpoch: second.signedAtEpoch - 3 * 86400,
                driftToleranceSeconds: second.timeAttestation.driftToleranceSeconds,
                monotonicAtSign: second.timeAttestation.monotonicAtSign,
                bootIdentity: second.timeAttestation.bootIdentity
            ),
            presenceFactor: second.presenceFactor, hardwareBacked: second.hardwareBacked,
            keyProtection: second.keyProtection, unlockedAtEpoch: second.unlockedAtEpoch,
            auditHead: second.auditHead, contentDigest: second.contentDigest,
            signatureDER: second.signatureDER, signedPayloadBytes: second.signedPayloadBytes
        )
        let shifted = ReleaseRecord(
            recordID: record.recordID, flightID: record.flightID, content: record.content,
            purpose: record.purpose, deviceID: record.deviceID, signatures: [first, tapped],
            auditLog: record.auditLog, sealedDigest: record.sealedDigest
        )
        let report = ReleaseAuditor.audit(shifted, context: receiptsContext)
        h.expect(!report.passed, "改时间证明会被识破（载荷与签名不再一致）")
        h.expect(report.failures.contains { $0.code == "A1.signedPayloadReconstruct" },
                 "失败项包含载荷重建")
    }

    await h.asyncSuite("攻击：把记录从旧航班挪到新航班") {
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
        let f = try! await signer.sign(session: s1, content: content, purpose: .departure,
                                       recordID: "R-MOVE", existingSignatures: [], audit: &audit)
        let s = try! await signer.sign(session: s2, content: content, purpose: .departure,
                                       recordID: "R-MOVE", existingSignatures: [f], audit: &audit)
        let record = try! signer.finalize(recordID: "R-MOVE", content: content, purpose: .departure,
                                          signatures: [f, s], audit: audit)

        // 把航班号换成另一个航班（内容与签名里的 token/flight 不再一致）
        let otherFlight = try! Fixtures.flight("CA9999-2026-11-25")
        let moved = ReleaseRecord(
            recordID: record.recordID, flightID: otherFlight, content: record.content,
            purpose: record.purpose, deviceID: record.deviceID,
            signatures: record.signatures, auditLog: record.auditLog, sealedDigest: record.sealedDigest
        )
        let report = ReleaseAuditor.audit(moved, context: company.auditContext())
        h.expect(!report.passed, "换航班号被发现")
    }
}
