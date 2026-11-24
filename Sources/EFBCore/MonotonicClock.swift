// MonotonicClock.swift
// 时间问题是本方案最容易被忽略、也最致命的一环：
// 驾驶舱没有网络，设备时间可以由用户手动修改，签字时间的可靠性直接决定
// "落地后公司能否核实这是本人当时所为"。
//
// 解决思路：可信时间锚（TimeAnchor）
//   * 联网时从公司时间服务取得已签名的 "权威当前时间 + 单调计数起点"；
//   * 离线期间以单调时钟（mach_continuous_time / 系统运行时长）推算；
//   * 设备重启会让单调时钟归零 => 锚失效，必须重新联网同步。
//
// 单调时钟本身不可被用户调整，且与挂钟一起前推，因此这是离线场景下能做到的最强保证。

import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// 单调时钟抽象：测试可注入假时钟来模拟时间流逝。
public protocol MonotonicClock: Sendable {
    /// 自设备（或开机）以来的连续单调秒数。不得回退。
    var uptimeSeconds: Double { get }
    /// 设备自最近一次开机以来的秒数，用于检测重启。
    var secondsSinceBoot: Double { get }
    /// 本次开机的身份标识（kern.boottime，秒）。重启后取值改变；
    /// 用户修改系统时间也**不会**改变它（boottime 是内核对本次启动的固定记录）。
    var bootIdentity: Double { get }
}

/// 生产实现：mach_continuous_time 不受休眠影响，且用户无法调整。
public struct SystemMonotonicClock: MonotonicClock {
    public init() {}

    public var uptimeSeconds: Double { Self.machContinuousSeconds() }

    public var secondsSinceBoot: Double { Self.machContinuousSeconds() }

    public var bootIdentity: Double { Self.bootTimeEpoch() }

    static func bootTimeEpoch() -> Double {
        var mib: [Int32] = [CTL_KERN, KERN_BOOTTIME]
        var tv = timeval()
        var size = MemoryLayout<timeval>.size
        guard sysctl(&mib, 2, &tv, &size, nil, 0) == 0 else { return 0 }
        return Double(tv.tv_sec) + Double(tv.tv_usec) / 1_000_000
    }

    private static func machContinuousSeconds() -> Double {
        var info = mach_timebase_info_data_t()
        mach_timebase_info(&info)
        let ticks = Double(mach_continuous_time())
        return ticks * Double(info.numer) / Double(info.denom) / 1_000_000_000
    }
}

/// 测试 / 演示用可控时钟。
public final class ManualClock: MonotonicClock, @unchecked Sendable {
    private let lock = NSLock()
    private var uptime: Double
    private var bootEpoch: Double

    public init(uptimeSeconds: Double = 100, bootIdentity: Double = 1_700_000_000) {
        self.uptime = uptimeSeconds
        self.bootEpoch = bootIdentity
    }

    public var uptimeSeconds: Double {
        lock.lock(); defer { lock.unlock() }
        return uptime
    }

    public var secondsSinceBoot: Double { uptimeSeconds }

    /// 手动时钟默认模拟同一次开机；reboot() 会换一个新的开机身份。
    public var bootIdentity: Double {
        lock.lock(); defer { lock.unlock() }
        return bootEpoch
    }

    public func setBootIdentity(_ epoch: Double) {
        lock.lock(); defer { lock.unlock() }
        bootEpoch = epoch
    }

    public func advance(by seconds: Double) {
        lock.lock(); defer { lock.unlock() }
        uptime += seconds
    }

    /// 模拟设备重启：单调时钟归零。
    public func reboot() {
        lock.lock(); defer { lock.unlock() }
        uptime = 0
        // 换一个开机身份，模拟 kernel boottime 改变
        bootEpoch += 1_000_000
    }
}

/// 可信时间锚：由公司时间服务签名，把 "权威时间" 钉在 "单调时钟读数" 上。
public struct TimeAnchor: Equatable, Sendable, CanonicalJSONEncodable, Codable {
    /// 锚定时的权威 UTC 时间（自 1970 的秒，允许小数）。
    public let authoritativeEpoch: Double
    /// 锚定时设备的单调时钟读数（秒）。
    public let monotonicAtAnchor: Double
    /// 锚签发时设备所在的那一次开机的身份（kern.boottime 秒）。
    /// 重启后该值必变，从而彻底排除"重启后把时间冻结在锚点"。
    public let bootIdentity: Double
    /// 锚的签发时间（权威秒），用于限制离线使用时长。
    public let issuedAtEpoch: Double
    /// 允许离线使用的最长秒数（例如 72 小时，覆盖最长航段 + 备份）。
    public let validitySeconds: Double
    /// 允许的最大时钟漂移（秒），由公司策略下发。
    public let driftToleranceSeconds: Double

    public init(
        authoritativeEpoch: Double,
        monotonicAtAnchor: Double,
        issuedAtEpoch: Double,
        validitySeconds: Double,
        driftToleranceSeconds: Double,
        bootIdentity: Double
    ) {
        self.authoritativeEpoch = authoritativeEpoch
        self.monotonicAtAnchor = monotonicAtAnchor
        self.issuedAtEpoch = issuedAtEpoch
        self.validitySeconds = validitySeconds
        self.driftToleranceSeconds = driftToleranceSeconds
        self.bootIdentity = bootIdentity
    }

    public var canonicalValue: CanonicalValue {
        .object([
            "authoritativeEpoch": .int(Int(authoritativeEpoch)),
            "bootIdentityMilliseconds": .int(Int((bootIdentity * 1000).rounded())),
            "driftToleranceSeconds": .int(Int(driftToleranceSeconds)),
            "issuedAtEpoch": .int(Int(issuedAtEpoch)),
            "monotonicAtAnchor": secondsLiteral(monotonicAtAnchor),
            "validitySeconds": .int(Int(validitySeconds)),
        ])
    }

    private func secondsLiteral(_ value: Double) -> CanonicalValue {
        // 单调读数可能带小数；为了规范化，四舍五入到毫秒并转整数（毫秒）。
        .int(Int((value * 1000).rounded()))
    }
}

/// 随签字一起封存的 "时间是怎么算出来的" 证明。
/// 审计方拿到公司的锚签发记录即可重算：signedEpoch 必须在 [anchoredEpoch, anchoredEpoch + validity] 内。
public struct TimeAttestation: Equatable, Sendable, CanonicalJSONEncodable, Codable {
    public let anchoredEpoch: Double
    public let monotonicAtAnchor: Double
    public let signedEpoch: Double
    public let driftToleranceSeconds: Double
    /// 签字瞬间的单调读数。审计方据此精确重算：
    /// expectedSigned = anchoredEpoch + (monotonicAtSign - monotonicAtAnchor)，
    /// 再与 signedEpoch 比对，容差仅需覆盖真实漂移，而不是整个 72 小时窗口。
    public let monotonicAtSign: Double
    /// 签字所在的那一次开机身份（须与锚一致）。
    public let bootIdentity: Double

    public init(
        anchoredEpoch: Double,
        monotonicAtAnchor: Double,
        signedEpoch: Double,
        driftToleranceSeconds: Double,
        monotonicAtSign: Double,
        bootIdentity: Double
    ) {
        self.anchoredEpoch = anchoredEpoch
        self.monotonicAtAnchor = monotonicAtAnchor
        self.signedEpoch = signedEpoch
        self.driftToleranceSeconds = driftToleranceSeconds
        self.monotonicAtSign = monotonicAtSign
        self.bootIdentity = bootIdentity
    }

    public var canonicalValue: CanonicalValue {
        .object([
            "anchoredEpoch": .int(Int(anchoredEpoch)),
            "bootIdentityMilliseconds": .int(Int((bootIdentity * 1000).rounded())),
            "driftToleranceSeconds": .int(Int(driftToleranceSeconds)),
            "monotonicAtAnchorMilliseconds": .int(Int((monotonicAtAnchor * 1000).rounded())),
            "monotonicAtSignMilliseconds": .int(Int((monotonicAtSign * 1000).rounded())),
            "signedEpoch": .int(Int(signedEpoch)),
        ])
    }

    /// 由单调读数推算的签字时刻。
    public var recomputedSignedEpoch: Double {
        anchoredEpoch + (monotonicAtSign - monotonicAtAnchor)
    }
}
