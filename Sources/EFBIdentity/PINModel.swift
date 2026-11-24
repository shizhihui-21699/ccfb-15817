// PINModel.swift
// PIN 的生命周期：设置、修改、重置。全部离线完成。
//
// 约束：
//   * 新 PIN 不得与最近 N 个历史 PIN 相同（历史只存派生值，不存明文）；
//   * 修改 PIN 必须先用旧 PIN 解封现有凭据（否则等于可以随意换人）；
//   * 修改后需要重新生成一颗密钥？——不需要。密钥的 applicationPassword 门禁
//     由系统 ACL 维护；应用侧只需替换"校验器"，并在下次解锁时用新 PIN 解锁密钥。
//     这里的关键取舍保留原密钥（证书绑定的是这颗公钥，换钥需要公司重签证书）。

import Foundation
import EFBCore
import EFBCryptography

public enum PINManagement {
    /// 在本机已有凭据上设置/更换 PIN（要求先通过旧 PIN）。
    public static func changePIN(
        crew: CrewID,
        oldPIN: SecureBytes,
        newPIN: SecureBytes,
        store: CrewCredentialStore,
        policy: CrewPolicy,
        time: TrustedTimeProviding
    ) throws {
        // 1) 旧 PIN 必须能解开密封载荷；且必须走与登录同一套锁定逻辑，
        //    否则"改 PIN"就成了绕过锁定、无限猜 PIN 的旁路。
        guard let record = try store.load(crew) else {
            throw EFBError.credentialMissing(crew: crew)
        }
        let sealingKey = SecureEnclaveSealingKey(blob: record.sealingKeyBlob)
        let plaintext = try sealingKey.open(record.sealedPayload)
        var payload = try JSONDecoder().decode(SealedCredentialPayload.self, from: plaintext)
        let now = try time.currentEpoch()
        try PINAttemptTracker.checkLockout(state: payload.attemptState, nowEpoch: now)
        guard try PINHasher.verify(pin: oldPIN, against: payload.pinVerifier) else {
            // 与 unlock 相同的顺序：先落盘失败计数，再抛出。
            let failure: EFBError
            do {
                try PINAttemptTracker.recordFailure(state: &payload.attemptState, policy: policy, nowEpoch: now)
                failure = .pinIncorrect(attemptsRemaining: 0)
            } catch let error as EFBError {
                failure = error
            }
            var failed = record
            failed.sealedPayload = try CredentialSealer.seal(
                try JSONEncoder().encode(payload), to: sealingKey.sealingPublicKeyX963
            )
            try store.save(failed)
            throw failure
        }

        // 2) 新 PIN 策略 + 历史查重（历史查重必须连"当前 PIN"一起比，
        //    否则第一次改 PIN 时可以原地改成同一个 PIN）
        try PINAttemptTracker.validatePolicy(pin: newPIN, policy: policy)
        if try PINHasher.verify(pin: newPIN, against: payload.pinVerifier) {
            throw EFBError.pinPolicyViolation(["不能与当前 PIN 相同"])
        }
        for historic in payload.pinHistory {
            if try PINHasher.verify(pin: newPIN, against: historic) {
                throw EFBError.pinPolicyViolation(["不能与最近 \(policy.pinHistoryDepth) 个 PIN 相同"])
            }
        }

        // 3) 先用旧 PIN 解出解锁密钥，再用新 PIN 重新包裹 —— 硬件密钥与证书都不变。
        let signingSecret = try PINWrap.unwrap(
            payload.wrappedSigningSecret, pin: oldPIN,
            salt: payload.wrapSalt, iterations: payload.wrapIterations
        )
        defer { signingSecret.wipe() }
        let rewrapped = try PINWrap.wrap(signingSecret, with: newPIN, iterations: payload.wrapIterations)

        // 4) 轮换校验器，旧校验器入历史（只保留 N 个）
        var history = payload.pinHistory
        history.append(payload.pinVerifier)
        payload.pinHistory = Array(history.suffix(policy.pinHistoryDepth))
        payload.pinVerifier = try PINHasher.makeVerifier(pin: newPIN, digits: newPIN.count)
        payload.attemptState = .empty
        payload.wrappedSigningSecret = rewrapped.wrapped
        payload.wrapSalt = rewrapped.salt
        payload.wrapIterations = rewrapped.iterations

        // 5) 重新密封
        var updated = record
        updated.sealedPayload = try CredentialSealer.seal(
            try JSONEncoder().encode(payload), to: sealingKey.sealingPublicKeyX963
        )
        try store.save(updated)
    }
}
