// Identifiers.swift
// 领域标识符。全部用带校验的字符串包装类型，避免把 CrewID 误传进 DeviceID 之类的参数位。

import Foundation

public enum EFBIdentifierSyntax {
    public static func validate(
        _ raw: String,
        field: String,
        maxLength: Int,
        uppercase: Bool
    ) throws -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-+")
        guard !trimmed.isEmpty else {
            throw EFBError.invalidIdentifier(field: field, value: raw, reason: "不能为空")
        }
        guard trimmed.count <= maxLength else {
            throw EFBError.invalidIdentifier(field: field, value: raw, reason: "超过 \(maxLength) 字符")
        }
        guard trimmed.unicodeScalars.allSatisfy({ allowed.contains($0) }) else {
            throw EFBError.invalidIdentifier(field: field, value: raw, reason: "含有不允许的字符")
        }
        return uppercase ? trimmed.uppercased() : trimmed
    }
}

/// 所有领域标识符共享的 Coding / 比较 / 展示行为。
public protocol EFBIdentifier: Hashable, Sendable, Codable, CustomStringConvertible, Comparable {
    var rawValue: String { get }
    static var fieldName: String { get }
    /// 必须是协议**要求**（而非仅扩展默认值），否则具体类型的重写不参与动态派发。
    static var maxLength: Int { get }
    static var uppercased: Bool { get }
    init(validating raw: String) throws
}

extension EFBIdentifier {
    public static var maxLength: Int { 64 }
    public static var uppercased: Bool { false }
    public var description: String { rawValue }
    public static func < (lhs: Self, rhs: Self) -> Bool { lhs.rawValue < rhs.rawValue }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let raw = try container.decode(String.self)
        try self.init(validating: raw)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }

    static func normalized(_ raw: String) throws -> String {
        try EFBIdentifierSyntax.validate(raw, field: fieldName, maxLength: maxLength, uppercase: uppercased)
    }
}

/// 机组成员号（例如 "P0042"）。大小写不敏感，内部统一大写。
public struct CrewID: EFBIdentifier {
    public static var fieldName: String { "CrewID" }
    public static var uppercased: Bool { true }
    public let rawValue: String
    public init(validating raw: String) throws { self.rawValue = try Self.normalized(raw) }
}

/// 设备标识（MDM 下发，例如 "IPAD-EFB-0123"）。
public struct DeviceID: EFBIdentifier {
    public static var fieldName: String { "DeviceID" }
    public let rawValue: String
    public init(validating raw: String) throws { self.rawValue = try Self.normalized(raw) }
}

/// 航班号 / 任务标识（例如 "CA1831-2026-11-24"）。
public struct FlightID: EFBIdentifier {
    public static var fieldName: String { "FlightID" }
    public static var maxLength: Int { 40 }
    public let rawValue: String
    public init(validating raw: String) throws { self.rawValue = try Self.normalized(raw) }
}

/// 放行令牌序列号（一次性、预发）。
public struct TokenSerial: EFBIdentifier {
    public static var fieldName: String { "TokenSerial" }
    public static var maxLength: Int { 32 }
    public static var uppercased: Bool { true }
    public let rawValue: String
    public init(validating raw: String) throws { self.rawValue = try Self.normalized(raw) }
}

/// 证书标识（由公钥指纹派生）。
public struct CertificateID: EFBIdentifier {
    public static var fieldName: String { "CertificateID" }
    public static var maxLength: Int { 48 }
    public let rawValue: String
    public init(validating raw: String) throws { self.rawValue = try Self.normalized(raw) }
}

/// 会话标识。
public struct SessionID: EFBIdentifier {
    public static var fieldName: String { "SessionID" }
    public let rawValue: String
    public init(validating raw: String) throws { self.rawValue = try Self.normalized(raw) }
}

/// 双人签名的角色。
public enum CrewRole: String, Codable, Sendable, CaseIterable, Comparable {
    case captain = "CAPTAIN"        // 机长
    case firstOfficer = "FIRST_OFFICER" // 副驾驶
    case reliefPilot = "RELIEF_PILOT"   // 加强机组成员（可替班）
    case instructor = "INSTRUCTOR"      // 教员（可替代任一座位）

    /// 该角色是否有资格占用某座位。
    public func canOccupy(_ seat: Seat) -> Bool {
        switch self {
        case .captain, .instructor:
            return true
        case .firstOfficer, .reliefPilot:
            return seat == .right
        }
    }

    public static func < (lhs: CrewRole, rhs: CrewRole) -> Bool {
        allCases.firstIndex(of: lhs)! < allCases.firstIndex(of: rhs)!
    }

    public var displayName: String {
        switch self {
        case .captain: return "机长"
        case .firstOfficer: return "副驾驶"
        case .reliefPilot: return "替班飞行员"
        case .instructor: return "教员"
        }
    }
}

/// 驾驶舱座位。
public enum Seat: String, Codable, Sendable, CaseIterable {
    case left = "LEFT_SEAT"    // 通常机长
    case right = "RIGHT_SEAT"  // 通常副驾驶

    public var displayName: String {
        switch self {
        case .left: return "左座"
        case .right: return "右座"
        }
    }

    public var counterpart: Seat {
        switch self {
        case .left: return .right
        case .right: return .left
        }
    }
}
