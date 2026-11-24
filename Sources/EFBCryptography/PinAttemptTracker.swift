// PinAttemptTracker.swift
// 连续失败锁定。完全本地，不依赖联网 —— 驾驶舱没有网络。
//
// 设计要点：
//   * 计数与锁定时刻写进 SecureStore（和凭据同一个条目，一并被吊销）；
//   * 锁定到期时间用可信时间（TimeAnchor 推算），而不是设备挂钟，防止用户把时间调回去；
//   * 每次成功核验清零，但保留 lastFailureEpoch 以便审计。

import Foundation
import EFBCore

public struct PINAttemptState: Equatable, Sendable, Codable {
    public var consecutiveFailures: Int
    public var lockoutUntilEpoch: Double?
    public var lastFailureEpoch: Double?
    public var totalFailures: Int

    public init(consecutiveFailures: Int = 0, lockoutUntilEpoch: Double? = nil, lastFailureEpoch: Double? = nil, totalFailures: Int = 0) {
        self.consecutiveFailures = consecutiveFailures
        self.lockoutUntilEpoch = lockoutUntilEpoch
        self.lastFailureEpoch = lastFailureEpoch
        self.totalFailures = totalFailures
    }

    public static let empty = PINAttemptState()
}

public enum PINAttemptTracker {
    /// 记录一次失败，返回剩余尝试数与可能的锁定。
    public static func recordFailure(
        state: inout PINAttemptState,
        policy: CrewPolicy,
        nowEpoch: Double
    ) throws {
        state.consecutiveFailures += 1
        state.totalFailures += 1
        state.lastFailureEpoch = nowEpoch

        if state.consecutiveFailures >= policy.maxPINAttempts {
            let grade = min(state.consecutiveFailures - policy.maxPINAttempts, policy.lockoutBackoffSeconds.count - 1)
            let backoff = Double(policy.lockoutBackoffSeconds[max(0, grade)])
            state.lockoutUntilEpoch = nowEpoch + backoff
            throw EFBError.pinLockedOut(retryAfter: backoff)
        }

        let remaining = policy.maxPINAttempts - state.consecutiveFailures
        throw EFBError.pinIncorrect(attemptsRemaining: remaining)
    }

    /// 在允许尝试前检查是否仍处于锁定。
    public static func checkLockout(state: PINAttemptState, nowEpoch: Double) throws {
        guard let until = state.lockoutUntilEpoch else { return }
        if nowEpoch < until {
            throw EFBError.pinLockedOut(retryAfter: until - nowEpoch)
        }
    }

    public static func recordSuccess(state: inout PINAttemptState) {
        state.consecutiveFailures = 0
        state.lockoutUntilEpoch = nil
    }

    /// PIN 策略校验（长度、纯数字、禁止与历史重复由调用方比对哈希）。
    public static func validatePolicy(pin: SecureBytes, policy: CrewPolicy) throws {
        let bytes = pin.data
        var violations: [String] = []
        let isAllDigits = bytes.allSatisfy { byte in
            (48...57).contains(byte)
        }
        if !isAllDigits { violations.append("PIN 只能包含数字") }
        if bytes.count < policy.pinMinDigits { violations.append("至少 \(policy.pinMinDigits) 位") }
        if bytes.count > policy.pinMaxDigits { violations.append("至多 \(policy.pinMaxDigits) 位") }
        // 排除连号与重复数字这类手套误触高发 PIN
        if isAllDigits, bytes.count >= 3 {
            let digits = bytes.map { Int($0) - 48 }
            if digits.allSatisfy({ $0 == digits[0] }) { violations.append("不能是重复数字") }
            if zip(digits, digits.dropFirst()).allSatisfy({ $1 == $0 + 1 }) { violations.append("不能是连续递增") }
        }
        if !violations.isEmpty { throw EFBError.pinPolicyViolation(violations) }
    }
}
