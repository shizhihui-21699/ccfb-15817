// AnchoredTimeProvider.swift
// 把 TimeAnchor + MonotonicClock 组合成协议，便于上层注入假时钟。

import Foundation

public protocol TrustedTimeProviding: Sendable {
    /// 当前可信 UTC 秒；锚失效时抛错，调用方必须阻止签字。
    func currentEpoch() throws -> Double
    /// 某时刻的时间证明（随签字一起封存）。
    func attestation(forEpoch epoch: Double) throws -> TimeAttestation
}

public struct AnchoredTimeProvider: TrustedTimeProviding {
    private let anchor: TimeAnchor
    private let clock: MonotonicClock

    public init(anchor: TimeAnchor, clock: MonotonicClock = SystemMonotonicClock()) throws {
        self.anchor = anchor
        self.clock = clock
    }

    public func currentEpoch() throws -> Double {
        try Self.validate(anchor)
        // 1) 开机身份必须与锚签发时相同。若不同（设备重启过），单调读数已归零，
        //    任何基于它的推算都不可信 —— 直接判锚失效，要求重新联网。
        //    注意：不能只比较"本次运行以来的秒数"，那样重启后可以重新构造 provider
        //    并把时间冻结在锚点（这是审计发现的真实缺陷）。
        if abs(clock.bootIdentity - anchor.bootIdentity) > 1 {
            throw EFBError.rebootSinceAnchor
        }
        // 2) 单调读数为负增量也说明时钟回退（防御性，bootIdentity 已应覆盖）。
        guard clock.uptimeSeconds >= anchor.monotonicAtAnchor - 1 else {
            throw EFBError.rebootSinceAnchor
        }
        // 3) 离线可用时长受锚的 validitySeconds 限制。
        let elapsed = clock.uptimeSeconds - anchor.monotonicAtAnchor
        if elapsed > anchor.validitySeconds {
            throw EFBError.timeAnchorExpired
        }
        return anchor.authoritativeEpoch + elapsed
    }

    public func attestation(forEpoch epoch: Double) throws -> TimeAttestation {
        TimeAttestation(
            anchoredEpoch: anchor.authoritativeEpoch,
            monotonicAtAnchor: anchor.monotonicAtAnchor,
            signedEpoch: epoch,
            driftToleranceSeconds: anchor.driftToleranceSeconds,
            monotonicAtSign: clock.uptimeSeconds,
            bootIdentity: anchor.bootIdentity
        )
    }

    public static func validate(_ anchor: TimeAnchor) throws {
        guard anchor.authoritativeEpoch > 0 else {
            throw EFBError.timeAnchorInvalid(reason: "authoritativeEpoch 非正")
        }
        guard anchor.monotonicAtAnchor >= 0 else {
            throw EFBError.timeAnchorInvalid(reason: "monotonicAtAnchor 为负")
        }
        guard anchor.bootIdentity > 0 else {
            throw EFBError.timeAnchorInvalid(reason: "锚缺少本次开机身份（无法抵御重启冻结时间）")
        }
        guard anchor.validitySeconds > 0, anchor.validitySeconds <= 30 * 24 * 3600 else {
            throw EFBError.timeAnchorInvalid(reason: "validitySeconds 超出 [1, 30 天]")
        }
    }
}

/// 测试用：固定时刻、可选择抛出失效错误。
public final class FixedTimeProvider: TrustedTimeProviding, @unchecked Sendable {
    private let lock = NSLock()
    private var epoch: Double
    private var failure: EFBError?

    public init(epoch: Double) {
        self.epoch = epoch
    }

    public func setEpoch(_ value: Double) {
        lock.lock(); defer { lock.unlock() }
        epoch = value
    }

    public func failWith(_ error: EFBError?) {
        lock.lock(); defer { lock.unlock() }
        failure = error
    }

    public func currentEpoch() throws -> Double {
        lock.lock(); defer { lock.unlock() }
        if let failure { throw failure }
        return epoch
    }

    public func attestation(forEpoch epoch: Double) throws -> TimeAttestation {
        TimeAttestation(anchoredEpoch: epoch, monotonicAtAnchor: 0, signedEpoch: epoch,
                        driftToleranceSeconds: 0, monotonicAtSign: 0, bootIdentity: 1_700_000_000)
    }
}
