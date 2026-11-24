// AuditEvent.swift
// 审计事件。所有身份 / 会话 / 签字状态变化都写入本地不可变日志（散列链），
// 落地后随签字一起上传，让公司能复现 "谁在什么时候做了什么"。

import Foundation

public enum AuditKind: String, Codable, Sendable, CaseIterable {
    case enrollment
    case pinChanged
    case unlock
    case unlockFailed
    case lockout
    case presenceCheck
    case grantIssued
    case sessionOpened
    case sessionLockedIdle
    case sessionClosed
    case handoverBegin
    case handoverCommitted
    case takeoverAuthorized
    case releaseSigned
    case releaseCompleted
    case tokenConsumed
    case timeAnchored
    case adminRevocation
}

/// 一条审计事件。seq 从 0 递增，previousHash 形成链。
public struct AuditEvent: Equatable, Sendable, CanonicalJSONEncodable, Codable {
    public let sequence: Int
    public let kind: AuditKind
    /// 事件发生时的可信 UTC 秒。
    public let atEpoch: Double
    /// 涉及的机组成员（可空，例如 adminRevocation 只针对其凭据）。
    public let crew: CrewID?
    /// 座位（会话相关事件）。
    public let seat: Seat?
    /// 自由说明（不承载敏感信息，例如 "state=locked"）。
    public let detail: String
    /// 上一事件的哈希；首事件为零哈希。
    public let previousHash: SHA256Digest

    public init(
        sequence: Int,
        kind: AuditKind,
        atEpoch: Double,
        crew: CrewID? = nil,
        seat: Seat? = nil,
        detail: String = "",
        previousHash: SHA256Digest
    ) {
        self.sequence = sequence
        self.kind = kind
        self.atEpoch = atEpoch
        self.crew = crew
        self.seat = seat
        self.detail = detail
        self.previousHash = previousHash
    }

    public var canonicalValue: CanonicalValue {
        var fields: [String: CanonicalValue] = [
            "sequence": .int(sequence),
            "kind": .string(kind.rawValue),
            "atEpoch": .int(Int(atEpoch)),
            "detail": .string(detail),
            "previousHash": .string(previousHash.hexString),
        ]
        if let crew { fields["crew"] = .string(crew.rawValue) }
        if let seat { fields["seat"] = .string(seat.rawValue) }
        return .object(fields)
    }

    public var hash: SHA256Digest { SHA256Digest(hashing: self) }
}

/// 追加式散列链审计日志。任何插入 / 删除都会破坏链。
public struct AuditLog: Equatable, Sendable, Codable {
    public private(set) var events: [AuditEvent]

    public init() {
        self.events = []
    }

    public init(events: [AuditEvent]) {
        self.events = events
    }

    public var headHash: SHA256Digest {
        events.last?.hash ?? .zero
    }

    public mutating func append(kind: AuditKind, atEpoch: Double, crew: CrewID? = nil, seat: Seat? = nil, detail: String = "") {
        let event = AuditEvent(
            sequence: events.count,
            kind: kind,
            atEpoch: atEpoch,
            crew: crew,
            seat: seat,
            detail: detail,
            previousHash: headHash
        )
        events.append(event)
    }

    /// 校验散列链完整性与序列号连续。
    public func verify() -> Bool {
        var expectedPrevious = SHA256Digest.zero
        for (index, event) in events.enumerated() {
            guard event.sequence == index else { return false }
            guard event.previousHash == expectedPrevious else { return false }
            expectedPrevious = event.hash
        }
        return true
    }
}
