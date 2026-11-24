// EFBError.swift
// 统一错误类型。所有对外抛出错误都带原因字段，便于在驾驶舱的低带宽日志里定位。

import Foundation

public enum EFBError: Error, Equatable, Sendable {
    // 标识符 / 编码
    case invalidIdentifier(field: String, value: String, reason: String)
    case invalidCanonicalJSON(String)
    case malformedEncoding(field: String)

    // 密码学
    case signatureInvalid(reason: String)
    case credentialInvalid(reason: String)
    case credentialExpired
    case credentialNotYetValid
    case chainUntrusted(reason: String)
    case keyUnavailable(reason: String)
    case keyBindingMismatch(reason: String)

    // 身份核验
    case pinPolicyViolation([String])
    case pinIncorrect(attemptsRemaining: Int)
    case pinLockedOut(retryAfter: TimeInterval)
    case presenceUnavailable(String)
    case presenceFailed(String)
    case credentialMissing(crew: CrewID)
    case credentialRevoked(crew: CrewID)
    case credentialDeviceMismatch(crew: CrewID, expected: DeviceID, actual: DeviceID)
    case duplicateCrew(CrewID)
    case roleNotPermitted(seat: Seat, role: CrewRole)

    // 会话 / 交接
    case seatOccupied(Seat)
    case handoverIncomplete(reason: String)
    case custodyGapUnacknowledged(seconds: TimeInterval)
    case sessionLocked(reason: String)
    case sessionStale(reason: String)
    case grantExpired
    case grantExhausted
    case grantScopeMismatch(reason: String)

    // 放行令牌
    case tokenInvalid(reason: String)
    case tokenExpired
    case tokenNotYetValid
    case tokenAlreadyConsumed(serial: TokenSerial)
    case tokenNotAuthorized(reason: String)

    // 时间
    case timeAnchorInvalid(reason: String)
    case timeAnchorExpired
    case timeBeyondTolerance(seconds: TimeInterval)
    case rebootSinceAnchor

    // 存储
    case secureStoreUnavailable(String)
    case secureStoreFailure(Int32)

    // 其它
    case internalError(String)
}

extension EFBError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case let .invalidIdentifier(field, value, reason):
            return "无效标识符 \(field)='\(value)'：\(reason)"
        case let .invalidCanonicalJSON(detail):
            return "规范化 JSON 无效：\(detail)"
        case let .malformedEncoding(field):
            return "字段编码格式错误：\(field)"
        case let .signatureInvalid(reason):
            return "签名验证失败：\(reason)"
        case let .credentialInvalid(reason):
            return "凭据无效：\(reason)"
        case .credentialExpired:
            return "凭据已过期"
        case .credentialNotYetValid:
            return "凭据尚未生效"
        case let .chainUntrusted(reason):
            return "证书链不受信任：\(reason)"
        case let .keyUnavailable(reason):
            return "密钥不可用：\(reason)"
        case let .keyBindingMismatch(reason):
            return "密钥绑定关系不匹配：\(reason)"
        case let .pinPolicyViolation(violations):
            return "PIN 不符合策略：" + violations.joined(separator: "; ")
        case let .pinIncorrect(remaining):
            return "PIN 错误，剩余 \(remaining) 次尝试"
        case let .pinLockedOut(retryAfter):
            return "尝试次数过多，请在 \(Int(retryAfter)) 秒后重试"
        case let .presenceUnavailable(reason):
            return "现场核验不可用：\(reason)"
        case let .presenceFailed(reason):
            return "现场核验未通过：\(reason)"
        case let .credentialMissing(crew):
            return "设备上没有机组成员 \(crew) 的凭据"
        case let .credentialRevoked(crew):
            return "机组成员 \(crew) 的凭据已被吊销"
        case let .credentialDeviceMismatch(crew, expected, actual):
            return "机组成员 \(crew) 的凭据绑定设备 \(expected)，当前设备 \(actual)"
        case let .duplicateCrew(crew):
            return "同一机组成员 \(crew) 不能同时占用两个座位"
        case let .roleNotPermitted(seat, role):
            return "角色 \(role.rawValue) 无资格占用 \(seat.displayName) 座位"
        case let .seatOccupied(seat):
            return "\(seat.displayName) 座位已有未解除的会话"
        case let .handoverIncomplete(reason):
            return "交接未完成：\(reason)"
        case let .custodyGapUnacknowledged(seconds):
            return "存在 \(Int(seconds)) 秒无人值守会话，须由接班机组显式确认后才能继续"
        case let .sessionLocked(reason):
            return "会话已锁定：\(reason)"
        case let .sessionStale(reason):
            return "会话已失效：\(reason)"
        case .grantExpired:
            return "本次签字授权已超时，请重新核验"
        case .grantExhausted:
            return "本次签字授权已用尽（每次签字都需要独立的现场核验）"
        case let .grantScopeMismatch(reason):
            return "签字授权范围不匹配：\(reason)"
        case let .tokenInvalid(reason):
            return "放行令牌无效：\(reason)"
        case .tokenExpired:
            return "放行令牌已过期"
        case .tokenNotYetValid:
            return "放行令牌尚未生效"
        case let .tokenAlreadyConsumed(serial):
            return "放行令牌 \(serial) 已被使用"
        case let .tokenNotAuthorized(reason):
            return "放行令牌未授权本次操作：\(reason)"
        case let .timeAnchorInvalid(reason):
            return "时间锚无效：\(reason)"
        case .timeAnchorExpired:
            return "时间锚已过期，需要联网同步"
        case let .timeBeyondTolerance(seconds):
            return "签字时间超出可信范围 \(Int(seconds)) 秒"
        case .rebootSinceAnchor:
            return "设备自上次时间同步后重启过，需要联网重新同步时间"
        case let .secureStoreUnavailable(reason):
            return "安全存储不可用：\(reason)"
        case let .secureStoreFailure(status):
            return "安全存储操作失败（OSStatus \(status)）"
        case let .internalError(detail):
            return "内部错误：\(detail)"
        }
    }
}
