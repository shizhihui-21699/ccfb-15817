// Policy.swift
// 公司可下发的安全策略。策略本身应当由公司签名（见 EFBRelease/PolicyEnvelope），
// 但为了保持本库可独立测试，这里先定义数据结构与默认值。

import Foundation

public struct CrewPolicy: Equatable, Sendable, CanonicalJSONEncodable, Codable {
    // MARK: PIN
    /// PIN 最少位数。戴手套时用大按键数字键盘，6 位是 ICAO 常见基线。
    public var pinMinDigits: Int
    public var pinMaxDigits: Int
    /// 禁止与历史 PIN 重复的条数。
    public var pinHistoryDepth: Int
    /// 连续错误多少次后锁定。
    public var maxPINAttempts: Int
    /// 锁定退避序列（秒），超过末尾则沿用末值。
    public var lockoutBackoffSeconds: [Int]

    // MARK: 现场核验
    /// 是否强制每次签字都要现场生物识别。Face ID 可穿透手套，是该场景的首选。
    public var presenceRequired: Bool
    /// 生物识别失败后允许回退到 PIN-only 的次数（0 = 不允许）。
    public var presenceFallbackAllowedPerSignature: Int

    // MARK: 授权凭据（grant）
    /// 一次核验产生的签字授权最长存活秒数。越短越能防止 "核验一次，签多份"。
    public var grantLifetimeSeconds: Double
    /// 一次核验可签发多少个签字记录（默认 1，即每次签字都要重新核验）。
    public var grantMaxUses: Int

    // MARK: 会话 / 交接
    /// 无操作多久后自动锁屏并要求重新核验。
    public var leaseIdleLockSeconds: Double
    /// 单个会话租约的最长时长（防止一个登录状态跨多个航段一直不换）。
    public var leaseMaxDurationSeconds: Double
    /// 交接时，上一位机组 "最后一次操作/解锁" 到接班机组登录之间允许的最大空窗。
    /// 超过则记为 custody gap，必须显式确认（或主管授权）后才能继续。
    public var custodyGapToleranceSeconds: Double
    /// 是否允许 "强制接管"（上一位机组不在场时），需要一次性接管授权。
    public var takeoverRequiresAuthorization: Bool

    // MARK: 放行
    /// 是否需要双人（正副驾驶）分别签字。
    public var requiresTwoPilotRelease: Bool
    /// 两次签字之间允许的最大间隔。
    public var maxIntervalBetweenSignaturesSeconds: Double

    // MARK: 时间
    /// 允许的时间漂移容差。
    public var clockDriftToleranceSeconds: Double

    public init(
        pinMinDigits: Int = 6,
        pinMaxDigits: Int = 12,
        pinHistoryDepth: Int = 3,
        maxPINAttempts: Int = 5,
        lockoutBackoffSeconds: [Int] = [30, 120, 600, 1800, 3600],
        presenceRequired: Bool = true,
        presenceFallbackAllowedPerSignature: Int = 0,
        grantLifetimeSeconds: Double = 90,
        grantMaxUses: Int = 1,
        leaseIdleLockSeconds: Double = 15 * 60,
        leaseMaxDurationSeconds: Double = 16 * 3600,
        custodyGapToleranceSeconds: Double = 10 * 60,
        takeoverRequiresAuthorization: Bool = true,
        requiresTwoPilotRelease: Bool = true,
        maxIntervalBetweenSignaturesSeconds: Double = 30 * 60,
        clockDriftToleranceSeconds: Double = 60
    ) {
        self.pinMinDigits = pinMinDigits
        self.pinMaxDigits = pinMaxDigits
        self.pinHistoryDepth = pinHistoryDepth
        self.maxPINAttempts = maxPINAttempts
        self.lockoutBackoffSeconds = lockoutBackoffSeconds
        self.presenceRequired = presenceRequired
        self.presenceFallbackAllowedPerSignature = presenceFallbackAllowedPerSignature
        self.grantLifetimeSeconds = grantLifetimeSeconds
        self.grantMaxUses = grantMaxUses
        self.leaseIdleLockSeconds = leaseIdleLockSeconds
        self.leaseMaxDurationSeconds = leaseMaxDurationSeconds
        self.custodyGapToleranceSeconds = custodyGapToleranceSeconds
        self.takeoverRequiresAuthorization = takeoverRequiresAuthorization
        self.requiresTwoPilotRelease = requiresTwoPilotRelease
        self.maxIntervalBetweenSignaturesSeconds = maxIntervalBetweenSignaturesSeconds
        self.clockDriftToleranceSeconds = clockDriftToleranceSeconds
    }

    public static let standard = CrewPolicy()

    public var canonicalValue: CanonicalValue {
        .object([
            "clockDriftToleranceSeconds": .int(Int(clockDriftToleranceSeconds)),
            "custodyGapToleranceSeconds": .int(Int(custodyGapToleranceSeconds)),
            "grantLifetimeSeconds": .int(Int(grantLifetimeSeconds)),
            "grantMaxUses": .int(grantMaxUses),
            "leaseIdleLockSeconds": .int(Int(leaseIdleLockSeconds)),
            "leaseMaxDurationSeconds": .int(Int(leaseMaxDurationSeconds)),
            "lockoutBackoffSeconds": .array(lockoutBackoffSeconds.map { .int($0) }),
            "maxIntervalBetweenSignaturesSeconds": .int(Int(maxIntervalBetweenSignaturesSeconds)),
            "maxPINAttempts": .int(maxPINAttempts),
            "pinHistoryDepth": .int(pinHistoryDepth),
            "pinMaxDigits": .int(pinMaxDigits),
            "pinMinDigits": .int(pinMinDigits),
            "presenceFallbackAllowedPerSignature": .int(presenceFallbackAllowedPerSignature),
            "presenceRequired": .bool(presenceRequired),
            "requiresTwoPilotRelease": .bool(requiresTwoPilotRelease),
            "takeoverRequiresAuthorization": .bool(takeoverRequiresAuthorization),
        ])
    }
}
