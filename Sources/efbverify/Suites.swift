// Suites.swift
// 校验套件：覆盖编码、时间、身份、签字、审计、交接、篡改。

import Foundation
import CryptoKit
import Security
import EFBCore
import EFBCryptography
import EFBIdentity
import EFBRelease
import EFBSession
import EFBCompany

let now0: Double = 1_700_000_000

func runCoreSuites(_ h: Harness) {
    h.suite("规范化 JSON") {
        let value = CanonicalValue.object([
            "zeta": .int(1), "alpha": .int(2), "Beta": .int(3), "_underscore": .int(4),
        ])
        h.expectEqual(
            value.canonicalString,
            #"{"Beta":3,"_underscore":4,"alpha":2,"zeta":1}"#,
            "对象键按 UTF-8 字节序排序"
        )
        h.expectEqual(
            CanonicalValue.object([
                "b": .object(["y": .bool(false), "x": .bool(true)]),
                "a": .array([.int(1), .string("two"), .object(["k": .int(0)])]),
            ]).canonicalString,
            #"{"a":[1,"two",{"k":0}],"b":{"x":true,"y":false}}"#,
            "无空白且嵌套有序"
        )
        h.expectEqual(
            CanonicalValue.string("quote\" slash\\ nl\n tab\t ctl\u{01} 中文").canonicalString,
            #""quote\" slash\\ nl\n tab\t ctl\u0001 中文""#,
            "字符串转义"
        )
        h.expectEqual(
            CanonicalValue.string("机身号=B-1234").canonicalString,
            "\"机身号=B-1234\"",
            "非 ASCII 按 UTF-8 输出"
        )
        h.expectEqual(CanonicalValue.int(-42).canonicalString, "-42", "负整数")
        h.expectThrowsAny("错误长度的摘要被拒绝") {
            _ = try SHA256Digest(bytes: Data(repeating: 0, count: 31))
        }
        h.expect(Data(hexadecimal: "00ff") == Data([0x00, 0xFF]), "十六进制解析")
        h.expectThrowsAny("标识符拒绝空格") { _ = try CrewID(validating: "P00 42") }
        h.expectEqual(try! CrewID(validating: " p0042 ").rawValue, "P0042", "CrewID 统一大写")
    }

    h.suite("可信时间锚") {
        let clock = ManualClock(uptimeSeconds: 100)
        let anchor = TimeAnchor(authoritativeEpoch: now0, monotonicAtAnchor: 100,
                                issuedAtEpoch: now0, validitySeconds: 72 * 3600, driftToleranceSeconds: 60,
                                bootIdentity: ManualClock().bootIdentity)
        let provider = try! AnchoredTimeProvider(anchor: anchor, clock: clock)
        h.expect(abs(try! provider.currentEpoch() - now0) < 0.001, "锚定时刻即为权威时间")
        clock.advance(by: 3600)
        h.expect(abs(try! provider.currentEpoch() - (now0 + 3600)) < 0.001, "时间随单调时钟推进")

        let shortClock = ManualClock(uptimeSeconds: 100)
        let short = try! AnchoredTimeProvider(
            anchor: TimeAnchor(authoritativeEpoch: now0, monotonicAtAnchor: 100,
                               issuedAtEpoch: now0, validitySeconds: 3600, driftToleranceSeconds: 60,
                               bootIdentity: ManualClock().bootIdentity),
            clock: shortClock
        )
        shortClock.advance(by: 3601)
        h.expectThrows(EFBError.timeAnchorExpired, "超过有效期后失效") { _ = try short.currentEpoch() }

        clock.advance(by: 0)
        // 重启：开机身份改变，即便重新构造 provider 也必须判失效（冻结时间攻击）
        let rebootClock = ManualClock(uptimeSeconds: 0, bootIdentity: 1_700_500_000)
        let reboot = try! AnchoredTimeProvider(anchor: anchor, clock: rebootClock)
        h.expectThrows(EFBError.rebootSinceAnchor, "设备重启后锚失效（含重新构造 provider）") { _ = try reboot.currentEpoch() }
        rebootClock.advance(by: 3 * 86400)
        h.expectThrows(EFBError.rebootSinceAnchor, "重启后过去数天也不能用旧锚签发时间") { _ = try reboot.currentEpoch() }
    }

    h.suite("审计散列链") {
        var log = AuditLog()
        log.append(kind: .enrollment, atEpoch: 1)
        log.append(kind: .unlock, atEpoch: 2)
        log.append(kind: .releaseSigned, atEpoch: 3)
        h.expect(log.verify(), "正常链可校验")
        h.expect(log.events[1].previousHash == log.events[0].hash, "前向指针正确")

        var events = log.events
        events[1] = AuditEvent(sequence: 1, kind: .unlock, atEpoch: 999, previousHash: events[0].hash)
        h.expect(!AuditLog(events: events).verify(), "改动事件内容会断链")

        var events2 = log.events
        events2.remove(at: 1)
        h.expect(!AuditLog(events: events2).verify(), "删除事件会被发现")
    }
}

func runCryptoSuites(_ h: Harness) {
    h.suite("Secure Enclave 真实密钥（硬件）") {
        guard SecureEnclave.isAvailable else {
            h.expect(false, "本机应支持 Secure Enclave")
            return
        }
        // 不含 applicationPassword 的 ACL：headless 下可直接生成与签名
        let key = try! SecureEnclaveSigningKey.generate(protection: .hardwareOnly)
        let message = Data("EFB canonical payload".utf8)
        let publicKey = key.publicKeyX963
        h.expect(publicKey.count == 65, "PS256 公钥为 65 字节 X9.63")
        h.expect(key.isHardwareBacked, "私钥由 Secure Enclave 保护")

        // sign 需要已解锁：hardwareOnly 时也无需 PIN，但我们仍走 unlock 以验证句柄路径
        try! key.unlock(withSecret: SecureBytes([0]), reason: "测试")
        let signature = try! key.sign(message, reason: "测试签字")
        h.expect(signature.count <= 96, "ECDSA 签名 DER 长度合理（\(signature.count) 字节）")
        h.expect(
            SignatureVerifier.verify(signatureDER: signature, data: message, publicKeyX963: publicKey),
            "签名可验"
        )
        h.expect(
            SignatureVerifier.verify(signatureDER: signature, digest: Data(SHA256Digest(hashing: message).bytes), publicKeyX963: publicKey),
            "摘要方式也能验签"
        )

        let otherMessage = Data("tampered".utf8)
        h.expect(
            !SignatureVerifier.verify(signatureDER: signature, data: otherMessage, publicKeyX963: publicKey),
            "错误内容的签名不通过"
        )

        // 恢复同一颗 SE 密钥（模拟 Keychain 里存的 blob）
        let restored = SecureEnclaveSigningKey.restore(blob: key.dataRepresentation, protection: .hardwareOnly)
        h.expectEqual(restored.publicKeyX963, publicKey, "从 blob 恢复后公钥一致")
        try! restored.unlock(withSecret: SecureBytes([0]), reason: "恢复")
        let signature2 = try! restored.sign(message, reason: "恢复后签字")
        h.expect(
            SignatureVerifier.verify(signatureDER: signature2, data: message, publicKeyX963: publicKey),
            "恢复后的密钥能签名并被验签"
        )
    }

    h.suite("Secure Enclave 密封密钥") {
        guard SecureEnclave.isAvailable else { return }
        let sealing = try! SecureEnclaveSealingKey.generate()
        let secret = Data("PIN 派生值与证书摘要".utf8)
        let box = try! CredentialSealer.seal(secret, to: sealing.sealingPublicKeyX963)
        let opened = try! sealing.open(box)
        h.expectEqual(opened, secret, "密封后可解封")

        // 另一颗 SE 密封密钥（模拟另一台设备）应解不开
        let stranger = try! SecureEnclaveSealingKey.generate()
        h.expectThrowsAny("另设备无法解封") { _ = try stranger.open(box) }

        // 篡改密文应被 AES-GCM 拒绝
        var tampered = box
        var bytes = [UInt8](tampered.ciphertext)
        bytes[bytes.count - 1] ^= 0xFF
        tampered = SealedBox(
            ephemeralPublicKeyX963: tampered.ephemeralPublicKeyX963,
            ciphertext: Data(bytes)
        )
        h.expectThrowsAny("篡改密文会被拒绝") { _ = try sealing.open(tampered) }
    }

    h.suite("PIN 校验器与锁定") {
        let pin = SecureBytes(Array("482913".utf8))
        let verifier = try! PINHasher.makeVerifier(pin: pin, digits: 6, iterations: 12_000)
        h.expect(try! PINHasher.verify(pin: pin, against: verifier), "正确 PIN 通过")
        h.expect(!(try! PINHasher.verify(pin: SecureBytes(Array("482914".utf8)), against: verifier)), "错误 PIN 失败")

        var state = PINAttemptState.empty
        let policy = CrewPolicy.standard
        h.expectThrowsAny("第一次错误") {
            try PINAttemptTracker.recordFailure(state: &state, policy: policy, nowEpoch: now0)
        }
        h.expect(state.consecutiveFailures == 1, "计数递增")
        for _ in 2...policy.maxPINAttempts {
            do {
                try PINAttemptTracker.recordFailure(state: &state, policy: policy, nowEpoch: now0)
            } catch {}
        }
        h.expect(state.lockoutUntilEpoch != nil, "超过次数后锁定")
        h.expectThrowsAny("锁定期内拒绝") {
            try PINAttemptTracker.checkLockout(state: state, nowEpoch: now0)
        }

        h.expectThrowsAny("拒绝连续数字") {
            try PINAttemptTracker.validatePolicy(pin: SecureBytes(Array("123456".utf8)), policy: policy)
        }
        h.expectThrowsAny("拒绝重复数字") {
            try PINAttemptTracker.validatePolicy(pin: SecureBytes(Array("777777".utf8)), policy: policy)
        }
        h.expectNoThrow("合法 PIN 通过策略") {
            try PINAttemptTracker.validatePolicy(pin: SecureBytes(Array("482913".utf8)), policy: policy)
        }
    }
}
