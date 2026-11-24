// BiometricGate.swift
// "人在场" 因素。驾驶舱共享平板上，设备级生物识别只能证明 "设备前有人"，
// 不能证明 "是哪位机组"。因此它必须与每位机组各自的 PIN + SE 密钥绑定使用。
//
// 手套场景：Face ID 不要求摘手套，是本场景首选；Touch ID 需手指接触，可由
// 机组在登机前预设，飞行中主要依赖 Face ID。均不可用时按策略回退。
//
// 生产实现用 LAContext，测试用 ScriptedPresenceGate 可编排成功/失败。

import Foundation
import LocalAuthentication
import EFBCore

public enum PresenceResult: Equatable, Sendable {
    /// 通过，附带所用因素（biometric / passcode / fallback）。
    case verified(factor: PresenceFactor)
    /// 用户取消。
    case cancelled
    /// 系统不可用（例如未设置 Face ID）。
    case unavailable(reason: String)
    /// 核验失败（识别不通过 / 被停用）。
    case failed(reason: String)
}

public enum PresenceFactor: String, Codable, Sendable {
    case biometric
    case devicePasscode
    case pinFallback
    case simulated
}

public protocol PresenceChecking: Sendable {
    /// 是否有可用的现场核验手段。
    func availability() -> Bool
    /// 发起一次现场核验。必须在签字动作内部调用，保证签字与在场是同一时刻。
    func evaluate(reason: String) async throws -> PresenceResult
}

/// 生产实现。
public struct LocalAuthenticationGate: PresenceChecking {
    public init() {}

    public func availability() -> Bool {
        let context = LAContext()
        return context.canEvaluatePolicy(.deviceOwnerAuthentication, error: nil) ||
               context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
    }

    public func evaluate(reason: String) async throws -> PresenceResult {
        let context = LAContext()
        context.localizedReason = reason
        context.localizedFallbackTitle = "使用设备密码"
        context.localizedCancelTitle = "取消"

        var error: NSError?
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            do {
                try await context.evaluatePolicy(
                    .deviceOwnerAuthenticationWithBiometrics,
                    localizedReason: reason
                )
                return .verified(factor: .biometric)
            } catch {
                // 用户主动取消与识别失败要区分：取消意味着放弃签字。
                if let laError = error as? LAError, laError.code == .userCancel || laError.code == .systemCancel {
                    return .cancelled
                }
                return .failed(reason: describe(error))
            }
        }

        // 无生物识别：退回设备密码（仍是 "在场" 证据，但强度较低，审计要记录）。
        do {
            try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
            return .verified(factor: .devicePasscode)
        } catch {
            if let laError = error as? LAError, laError.code == .userCancel || laError.code == .systemCancel {
                return .cancelled
            }
            if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: nil) == false {
                return .unavailable(reason: describe(error))
            }
            return .failed(reason: describe(error))
        }
    }

    private func describe(_ error: Error) -> String {
        if let laError = error as? LAError {
            switch laError.code {
            case .biometryNotAvailable: return "设备不支持生物识别"
            case .biometryNotEnrolled: return "尚未录入生物识别"
            case .biometryLockout: return "生物识别被锁定"
            default: return laError.localizedDescription
            }
        }
        return error.localizedDescription
    }
}

/// 可编排的模拟门禁：测试与离线演示用。
public actor ScriptedPresenceGate: PresenceChecking {
    private var outcomes: [PresenceResult]
    private var defaultOutcome: PresenceResult
    private(set) var invocationCount: Int = 0

    public init(defaultOutcome: PresenceResult = .verified(factor: .simulated)) {
        self.defaultOutcome = defaultOutcome
        self.outcomes = []
    }

    /// 预排接下来若干次核验的结果，按 FIFO 消耗。
    public func script(_ results: [PresenceResult]) {
        outcomes.append(contentsOf: results)
    }

    public func setDefault(_ result: PresenceResult) {
        defaultOutcome = result
    }

    public nonisolated func availability() -> Bool { true }

    public func evaluate(reason: String) async throws -> PresenceResult {
        invocationCount += 1
        if !outcomes.isEmpty { return outcomes.removeFirst() }
        return defaultOutcome
    }

    public var calls: Int { invocationCount }
}

/// 明确禁止在无需在场证明时不静默通过。
public struct DenyAllPresenceGate: PresenceChecking {
    public init() {}
    public func availability() -> Bool { true }
    public func evaluate(reason: String) async throws -> PresenceResult {
        .failed(reason: "此设备已禁用现场核验")
    }
}
