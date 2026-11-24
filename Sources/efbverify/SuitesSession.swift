// SuitesSession.swift
// 交接、锁屏、接管授权、custody gap。

import Foundation
import EFBCore
import EFBCryptography
import EFBIdentity
import EFBRelease
import EFBSession
import EFBCompany

func runSessionSuites(_ h: Harness) {
    h.suite("会话交接与空闲锁屏") {
        let company = try! TestCompany(nowEpoch: now0)
        let device = try! TestDevice(deviceID: "IPAD-EFB-0123", nowEpoch: now0)
        let captainA = try! Fixtures.crew("P0042")
        let captainB = try! Fixtures.crew("P0099")
        _ = try! Fixtures.enroll(crew: captainA, seat: .left, role: .captain,
                                 pinDigits: "482913", device: device, company: company)
        _ = try! Fixtures.enroll(crew: captainB, seat: .left, role: .captain,
                                 pinDigits: "560284", device: device, company: company)

        let authenticator = device.authenticator(
            anchor: company.anchor, issuers: [company.issuerRecord], revocation: company.revocation
        )
        let sessions = SessionManager(policy: .standard, time: device.time, deviceID: device.deviceID)
        var audit = AuditLog()

        // 1) 上一位机长登录
        let a = try! authenticator.unlock(crew: captainA, seat: .left,
                                          pin: SecureBytes(Array("482913".utf8)), audit: &audit)
        let first = try! sessions.openSession(a, at: .left, audit: &audit)
        h.expectEqual(first.method, .initialSignIn, "首次登录标记为 initialSignIn")

        // 2) 上一位机长未登出，下一位直接登录 → 必须被拒绝，防止"顶掉"
        let b = try! authenticator.unlock(crew: captainB, seat: .left,
                                          pin: SecureBytes(Array("560284".utf8)), audit: &audit)
        h.expectThrows(EFBError.seatOccupied(.left), "未登出的活跃会话阻止他人顶替") {
            _ = try sessions.openSession(b, at: .left, audit: &audit)
        }

        // 3) 主动登出后可正常交接
        try! sessions.signOut(seat: .left, audit: &audit)
        h.expect(sessions.occupant(of: .left) == nil, "登出后座位空闲")
        h.expect(a.isDisposed, "登出后旧会话的 PIN 门禁被作废")
        h.expectThrowsAny("已 dispose 的会话不能再签字") {
            _ = try a.signingKey.sign(Data("x".utf8), reason: "测试")
        }

        let second = try! sessions.openSession(b, at: .left, audit: &audit)
        h.expectEqual(second.method, .inPerson, "正常交接标记为 inPerson")
        h.expectEqual(second.fromCrew, captainA, "记录上一位机组")
        h.expectEqual(second.toCrew, captainB, "记录接班机组")

        // 4) 同一人不能占两个座位
        let thirdDevice = try! TestDevice(deviceID: "IPAD-EFB-0123", nowEpoch: now0)
        _ = thirdDevice
        h.expectThrows(EFBError.duplicateCrew(captainB), "同一机组不能占两个座位") {
            _ = try sessions.openSession(b, at: .right, audit: &audit)
        }

        // 5) 空闲锁屏：超过阈值会丢弃 SE 门禁
        device.advance(by: device.policy.leaseIdleLockSeconds + 10)
        let locked = sessions.lockIdleSessions(at: try! device.time.currentEpoch(), audit: &audit)
        h.expectEqual(locked, [Seat.left], "空闲超时锁定左座")
        h.expect(!b.signingKey.isUnlocked, "锁屏后签字密钥回到锁定状态")

        // 6) 锁屏后重新输入 PIN 恢复当前会话（不是新开会话）
        h.expectThrowsAny("错误 PIN 无法恢复") {
            try authenticator.resume(session: b, pin: SecureBytes(Array("000000".utf8)), audit: &audit)
        }
        h.expectNoThrow("正确 PIN 恢复当前会话") {
            try authenticator.resume(session: b, pin: SecureBytes(Array("560284".utf8)), audit: &audit)
        }
        h.expect(b.signingKey.isUnlocked, "恢复后签字密钥可用")
        h.expectEqual(sessions.occupant(of: .left)?.sessionID, b.sessionID, "恢复不改变 sessionID")
    }

    h.suite("接管授权（上一位机组不在场）") {
        let company = try! TestCompany(nowEpoch: now0)
        let device = try! TestDevice(deviceID: "IPAD-EFB-0123", nowEpoch: now0)
        let captainA = try! Fixtures.crew("P0042")
        let captainB = try! Fixtures.crew("P0099")
        _ = try! Fixtures.enroll(crew: captainA, seat: .left, role: .captain,
                                 pinDigits: "482913", device: device, company: company)
        _ = try! Fixtures.enroll(crew: captainB, seat: .left, role: .captain,
                                 pinDigits: "560284", device: device, company: company)

        let authenticator = device.authenticator(
            anchor: company.anchor, issuers: [company.issuerRecord], revocation: company.revocation
        )
        let sessions = SessionManager(policy: .standard, time: device.time, deviceID: device.deviceID)
        var audit = AuditLog()

        let a = try! authenticator.unlock(crew: captainA, seat: .left,
                                          pin: SecureBytes(Array("482913".utf8)), audit: &audit)
        _ = try! sessions.openSession(a, at: .left, audit: &audit)

        // 无授权 → 拒绝
        let b = try! authenticator.unlock(crew: captainB, seat: .left,
                                          pin: SecureBytes(Array("560284".utf8)), audit: &audit)
        h.expectThrows(EFBError.seatOccupied(.left), "无授权时不能接管活跃会话") {
            _ = try sessions.openSession(b, at: .left, audit: &audit)
        }

        // 主管签发接管授权
        let auth = try! company.authority.issueTakeoverAuthorization(
            authorizationID: "TA-001", device: device.deviceID, seat: .left, subjectCrew: captainA,
            issuerID: company.issuerID, issuerKey: company.issuerKey
        )

        // 伪造的授权（用另一把私钥签发）应被拒绝
        let forgedKey = SoftwareSigningKey()
        let forged = try! company.authority.issueTakeoverAuthorization(
            authorizationID: "TA-002", device: device.deviceID, seat: .left, subjectCrew: captainA,
            issuerID: company.issuerID, issuerKey: forgedKey
        )
        h.expectThrowsAny("伪造的接管授权被拒绝") {
            _ = try sessions.openSession(b, at: .left, takeoverAuthorization: forged,
                                         trustedTakeoverIssuerKey: company.issuerKey.publicKeyX963, audit: &audit)
        }

        let record = try! sessions.openSession(
            b, at: .left, takeoverAuthorization: auth,
            trustedTakeoverIssuerKey: company.issuerKey.publicKeyX963, audit: &audit
        )
        h.expectEqual(record.method, .authorizedTakeover, "有效授权可接管")
        h.expectEqual(record.authorizationReference, "TA-001", "记录授权编号")
        h.expect(a.isDisposed, "接管后旧会话立即失效")
        h.expect(audit.verify(), "接管后审计链完整")

        // 同一张接管授权不可重放：座位再次被占用时，不能再用 TA-001 踢人
        let c = try! authenticator.unlock(crew: captainA, seat: .left,
                                          pin: SecureBytes(Array("482913".utf8)), audit: &audit)
        // captainB 此刻仍占着左座（接管后），captainA 不能顶替；再试同一张授权也不能
        h.expectThrowsAny("接管授权一次性，不能重放") {
            _ = try sessions.openSession(c, at: .left, takeoverAuthorization: auth,
                                         trustedTakeoverIssuerKey: company.issuerKey.publicKeyX963, audit: &audit)
        }
    }

    h.suite("无人值守空窗（custody gap）") {
        let company = try! TestCompany(nowEpoch: now0)
        let device = try! TestDevice(deviceID: "IPAD-EFB-0123", nowEpoch: now0)
        let captainA = try! Fixtures.crew("P0042")
        let captainB = try! Fixtures.crew("P0099")
        _ = try! Fixtures.enroll(crew: captainA, seat: .left, role: .captain,
                                 pinDigits: "482913", device: device, company: company)
        _ = try! Fixtures.enroll(crew: captainB, seat: .left, role: .captain,
                                 pinDigits: "560284", device: device, company: company)
        let authenticator = device.authenticator(
            anchor: company.anchor, issuers: [company.issuerRecord], revocation: company.revocation
        )
        let sessions = SessionManager(policy: .standard, time: device.time, deviceID: device.deviceID)
        var audit = AuditLog()

        let a = try! authenticator.unlock(crew: captainA, seat: .left,
                                          pin: SecureBytes(Array("482913".utf8)), audit: &audit)
        _ = try! sessions.openSession(a, at: .left, audit: &audit)
        // 长时间离开（可能是无人值守）
        device.advance(by: device.policy.custodyGapToleranceSeconds + 60)
        sessions.recordActivity(seat: .left, at: try! device.time.currentEpoch())
        try! sessions.signOut(seat: .left, audit: &audit)
        device.advance(by: device.policy.custodyGapToleranceSeconds + 60)

        let b = try! authenticator.unlock(crew: captainB, seat: .left,
                                          pin: SecureBytes(Array("560284".utf8)), audit: &audit)
        h.expectThrowsAny("空窗超过阈值需显式确认") {
            _ = try sessions.openSession(b, at: .left, audit: &audit)
        }
        let record = try! sessions.openSession(b, at: .left, acknowledgeCustodyGap: true, audit: &audit)
        h.expectEqual(record.method, .custodyGapAcknowledged, "确认后以 custody gap 方式接管")
        h.expect(record.custodyGapSeconds > device.policy.custodyGapToleranceSeconds, "记录空窗时长")
    }
}
