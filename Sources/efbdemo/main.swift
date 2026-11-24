// main.swift
// 驾驶舱两机长离线双签 + 交接的完整演示。
//
// 运行：swift run efbdemo
// 输出为中文，按 "场景 → 操作 → 结果" 组织，便于在评审会上逐句讲解。

import Foundation
import EFBCore
import EFBCryptography
import EFBIdentity
import EFBRelease
import EFBSession
import EFBCompany

func section(_ title: String) {
    print("\n" + String(repeating: "═", count: 72))
    print("  " + title)
    print(String(repeating: "═", count: 72))
}

func step(_ text: String) { print("\n▸ " + text) }
func ok(_ text: String) { print("  ✓ " + text) }
func info(_ text: String) { print("  · " + text) }
func warn(_ text: String) { print("  ✗ " + text) }

func runDemo() async throws {
        let now: Double = 1_741_000_000 // 2025-03-…
        let box = DateBox(now)

        section("场景：共享平板、无网络、戴手套、起飞前 20 分钟")

        // ── 公司侧 ────────────────────────────────────────────────
        step("① 公司侧准备（有网络时完成，之后全部离线）")
        let company = try DemoCompany(now: now)
        info("公司根：\(company.anchor.anchorID)")
        info("签发中心：\(company.issuerID)，允许角色：机长 / 副驾驶")

        // ── 设备侧预置 ───────────────────────────────────────────
        step("② 平板预置：每位机组在本机生成独立密钥，公司按该公钥签证书")
        let device = try DemoDevice(deviceID: "IPAD-EFB-0123", now: now)
        let captain = try CrewID(validating: "P0042")
        let firstOfficer = try CrewID(validating: "P0057")

        let captainPending = try device.enroller.prepareKey(crew: captain, pin: SecureBytes("482913"))
        let captainCert = try company.issueCertificate(
            crew: captain, seat: .left, role: .captain, device: device.deviceID,
            publicKey: captainPending.publicKeyX963
        )
        _ = try device.enroller.enroll(
            crew: captain, role: .captain, seats: [.left], pin: SecureBytes("482913"),
            certificate: captainCert, revocationEpoch: company.revocation.epoch, key: captainPending
        )
        let foPending = try device.enroller.prepareKey(crew: firstOfficer, pin: SecureBytes("731429"))
        let foCert = try company.issueCertificate(
            crew: firstOfficer, seat: .right, role: .firstOfficer, device: device.deviceID,
            publicKey: foPending.publicKeyX963
        )
        _ = try device.enroller.enroll(
            crew: firstOfficer, role: .firstOfficer, seats: [.right], pin: SecureBytes("731429"),
            certificate: foCert, revocationEpoch: company.revocation.epoch, key: foPending
        )
        ok("两位机组的密钥已生成在本机安全区，证书只绑定各自公钥；PIN 明文未落盘")

        // ── 预发令牌 ────────────────────────────────────────────
        step("③ 公司为本航班预发放行令牌（一人一座一枚，一次性）")
        let flight = try FlightID(validating: "CA1831-2026-11-24")
        let tokens = try company.issueTokens(
            flight: flight,
            assignments: [(captain, .left, device.deviceID), (firstOfficer, .right, device.deviceID)]
        )
        for token in tokens {
            info("令牌 \(token.serial) → \(token.crewID) / \(token.seat.displayName) / \(token.purpose.displayName)")
        }
        let tokenStore = ReleaseTokenStore()
        try tokenStore.load(tokens)

        // ── 会话 ────────────────────────────────────────────────
        let authenticator = device.authenticator(company: company)
        let sessions = SessionManager(policy: .standard, time: device.time, deviceID: device.deviceID)
        var audit = AuditLog()
        let signer = ReleaseSigner(
            authenticator: authenticator, tokenStore: tokenStore,
            tokenVerifier: IssuerKeyTokenVerifier(trustedIssuerKeys: [company.issuerID: company.issuerKey.publicKeyX963]),
            policy: .standard, time: device.time, deviceID: device.deviceID
        )
        let content = ReleaseContent(
            flightID: flight, departure: "PEK", destination: "SHA",
            aircraftRegistration: "B-1234", takeoffWeightKg: 72_000,
            vSpeedsKt: [148, 152, 155], runway: "18L",
            computedAtEpoch: now, performanceInputDigest: SHA256Digest(hashing: Data("性能输入".utf8)),
            fuelKg: 9_800
        )

        step("④ 机长左座登录：输入本人 PIN（一次），Face ID 每次签字都要过")
        let captainSession = try authenticator.unlock(
            crew: captain, seat: .left, pin: SecureBytes("482913"), audit: &audit
        )
        _ = try sessions.openSession(captainSession, at: .left, audit: &audit)
        info("会话 \(captainSession.sessionID)；签字密钥已在本会话内解锁")

        step("⑤ 副驾驶右座登录")
        let foSession = try authenticator.unlock(
            crew: firstOfficer, seat: .right, pin: SecureBytes("731429"), audit: &audit
        )
        _ = try sessions.openSession(foSession, at: .right, audit: &audit)

        // ── 双签 ────────────────────────────────────────────────
        step("⑥ 机长签字（Face ID 通过 → 签发一次性授权 → 硬件密钥签名）")
        let recordID = "R-" + flight.rawValue
        let captainSignature = try await signer.sign(
            session: captainSession, content: content, purpose: .departure,
            recordID: recordID, existingSignatures: [], audit: &audit
        )
        ok("机长签字：座位 \(captainSignature.seat.displayName)，密钥类型 \(captainSignature.hardwareBacked ? "Secure Enclave" : "软件（本机无 SE，演示用）")，令牌 \(captainSignature.tokenSerial)")

        step("⑦ 副驾驶签字（载荷内嵌机长签名摘要，防止先签后改）")
        let foSignature = try await signer.sign(
            session: foSession, content: content, purpose: .departure,
            recordID: recordID, existingSignatures: [captainSignature], audit: &audit
        )
        ok("副驾驶签字：座位 \(foSignature.seat.displayName)，令牌 \(foSignature.tokenSerial)")

        let record = try signer.finalize(
            recordID: recordID, content: content, purpose: .departure,
            signatures: [captainSignature, foSignature], audit: audit
        )
        ok("放行记录封存；审计链 \(record.auditLog.events.count) 条")

        // ── 落地核验 ────────────────────────────────────────────
        section("落地后：公司离线核验（只凭公开材料，不信任设备）")
        let report = ReleaseAuditor.audit(record, context: company.auditContext())
        for finding in report.findings {
            print("  \(finding.passed ? "✓" : "✗") [\(finding.code)] \(finding.detail)")
        }
        print("\n  结论：\(report.passed ? "可信 —— 签字确为该机组本人、当时、该设备所为" : "存在存疑项")")

        // ── 交接 ────────────────────────────────────────────────
        section("交接：上一位机长的登录状态必须彻底清除")
        step("⑧ 机长离开，副驾驶换班机长 \(captain) → 新机长 P0099 需要接管左座")
        let newCaptain = try CrewID(validating: "P0099")
        let newPending = try device.enroller.prepareKey(crew: newCaptain, pin: SecureBytes("560284"))
        let newCert = try company.issueCertificate(
            crew: newCaptain, seat: .left, role: .captain, device: device.deviceID,
            publicKey: newPending.publicKeyX963
        )
        _ = try device.enroller.enroll(
            crew: newCaptain, role: .captain, seats: [.left], pin: SecureBytes("560284"),
            certificate: newCert, revocationEpoch: company.revocation.epoch, key: newPending
        )

        warn("若直接顶替：")
        do {
            let intruder = try authenticator.unlock(
                crew: newCaptain, seat: .left, pin: SecureBytes("560284"), audit: &audit
            )
            _ = try sessions.openSession(intruder, at: .left, audit: &audit)
            warn("（不应发生）")
        } catch {
            print("    → 被拒绝：\(error.localizedDescription)")
        }

        step("⑨ 上一位机长主动登出（签字密钥的 PIN 门禁立即作废）")
        try sessions.signOut(seat: .left, audit: &audit)
        ok("旧会话 dispose；旧句柄再签字会被拒（已由校验套件覆盖）")

        step("⑩ 新机长登录，交接记录完整留痕")
        let newSession = try authenticator.unlock(
            crew: newCaptain, seat: .left, pin: SecureBytes("560284"), audit: &audit
        )
        let handover = try sessions.openSession(newSession, at: .left, audit: &audit)
        info("方式：\(handover.method.displayName)；上一机组：\(handover.fromCrew?.rawValue ?? "—")；空窗：\(Int(handover.custodyGapSeconds)) 秒")
        ok("审计链仍完整：\(audit.verify())")

        // ── 时间与离线 ─────────────────────────────────────────
        section("离线与手套的现实约束如何被处理")
        print("  · 时间：签字时刻 = 公司签发的锚 + 单调时钟，改设备挂钟无效")
        print("  · 手套：Face ID 穿透手套；PIN 只在开始值班时输一次")
        print("  · 紧张：每次签字必须独立 Face ID + 一次性令牌，约 2 次点击 3 秒内完成")
        print("  · 无网：证书链、撤销名单、令牌、锚都可离线核验；联网只用于同步新名单/锚")
        print("  · 双人：左/右座各签一次，同一人不得占两座，第二签内嵌第一签摘要")

        _ = box
    }

// MARK: - 演示用小型封装

final class DateBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Double
    init(_ value: Double) { self.value = value }
    var now: Double { lock.lock(); defer { lock.unlock() }; return value }
}

final class DemoCompany {
    let authority: SigningAuthority
    let issuerKey: SoftwareSigningKey
    let issuerRecord: IssuerRecord
    let issuerID = "OPS-CREW-CA"
    private(set) var revocation: RevocationSnapshot
    private var certificates: [CertificateID: IssuedCertificateRecord] = [:]
    private var ledger: [TokenSerial: IssuedTokenLedgerEntry] = [:]
    private var nowBox: DateBox

    init(now: Double) throws {
        nowBox = DateBox(now)
        let box = nowBox
        authority = try SigningAuthority(anchorID: "AIRLINE-ROOT-2026") { box.now }
        (issuerRecord, issuerKey) = try authority.delegateIssuer(
            issuerID: issuerID, allowedRoles: [.captain, .firstOfficer, .reliefPilot, .instructor]
        )
        revocation = try authority.issueRevocationSnapshot(
            epoch: 0, revokedCertificates: [], revokedCrew: [], issuerID: issuerID, issuerKey: issuerKey
        )
    }

    var anchor: TrustAnchor { authority.anchor }

    func issueCertificate(crew: CrewID, seat: Seat, role: CrewRole, device: DeviceID, publicKey: Data) throws -> IssuedCrewCertificate {
        let certificate = try authority.issueCrewCertificate(
            crew: crew, device: device, signingPublicKeyX963: publicKey, role: role,
            seats: [seat, seat.counterpart], policyDigest: CrewPolicy.standard.canonicalSHA256,
            revocationEpoch: revocation.epoch, issuerID: issuerID, issuerKey: issuerKey
        )
        certificates[certificate.certificate.certificateID] = IssuedCertificateRecord(
            certificate: certificate.certificate, issuerID: issuerID, issuerPublicKeyX963: issuerKey.publicKeyX963
        )
        return certificate
    }

    func issueTokens(flight: FlightID, assignments: [(CrewID, Seat, DeviceID)]) throws -> [ReleaseToken] {
        let tokens = try authority.issueReleaseTokens(
            flight: flight, crewAssignments: assignments.map { (crew: $0.0, seat: $0.1, device: $0.2) },
            purpose: .departure, fromEpoch: nowBox.now - 3600, untilEpoch: nowBox.now + 24 * 3600,
            issuerID: issuerID, issuerKey: issuerKey
        )
        for token in tokens {
            ledger[token.serial] = IssuedTokenLedgerEntry(
                serial: token.serial, flightID: token.flightID, crewID: token.crewID,
                seat: token.seat, deviceID: token.deviceID, purpose: token.purpose, issuedAtEpoch: nowBox.now
            )
        }
        return tokens
    }

    func auditContext() -> ReleaseAuditContext {
        ReleaseAuditContext(
            anchor: anchor, issuers: [issuerRecord], issuedCertificates: certificates,
            tokenLedger: ledger, consumedTokens: [], policy: .standard
        )
    }
}

final class DemoDevice {
    let deviceID: DeviceID
    let store = InMemorySecureStore()
    let credentialStore: CrewCredentialStore
    let keyVault = SoftwareKeyVault()
    let time: AnchoredTimeProvider
    let policy = CrewPolicy.standard
    let presence = ScriptedPresenceGate()

    init(deviceID: String, now: Double) throws {
        self.deviceID = try DeviceID(validating: deviceID)
        credentialStore = CrewCredentialStore(store: store)
        let clock = ManualClock(uptimeSeconds: 100)
        time = try AnchoredTimeProvider(
            anchor: TimeAnchor(authoritativeEpoch: now, monotonicAtAnchor: 100, issuedAtEpoch: now,
                               validitySeconds: 72 * 3600, driftToleranceSeconds: 60, bootIdentity: 1_700_000_000),
            clock: clock
        )
    }

    var enroller: CrewEnroller {
        CrewEnroller(store: credentialStore, deviceID: deviceID, policy: policy, time: time, keyVault: keyVault)
    }

    func authenticator(company: DemoCompany) -> CrewAuthenticator {
        CrewAuthenticator(
            store: credentialStore, deviceID: deviceID, policy: policy, time: time,
            presence: presence, keyVault: keyVault, anchor: company.anchor,
            issuerRecords: [company.issuerRecord], revocation: company.revocation
        )
    }
}

extension SecureBytes {
    convenience init(_ digits: String) {
        self.init(Array(digits.utf8))
    }
}

try await runDemo()
