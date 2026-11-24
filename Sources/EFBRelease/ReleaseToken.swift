// ReleaseToken.swift
// 预发一次性放行令牌（Pre-issued One-Time Release Token）。
//
// 为什么需要它：
//   * 离线时无法实时查 "这次航班是否已被公司放行"；
//   * 但如果完全凭设备自行判断，设备被拿走 / 应用被改，就能伪造放行。
//
// 方案：公司在本场（有网络时）为每个待执行航班预发一组令牌，令牌本身是
// "航班 + 座位 + 机组 + 有效期 + 序列号" 的签名凭据，离线存进设备。
// 签字时消耗对应座位的令牌，并把序列号写进签字记录。落地后公司凭自己的
// 签发清单确认：该序列号确实发给了这位机组、这个航班，且只用过一次。
//
// 这同时解决 "借用他人账号" 的一个关键环节：令牌与机组身份绑定，
// 另一位机组即便拿到 PIN，也没有属于他本人的令牌可消耗。

import Foundation
import EFBCore
import EFBCryptography
import EFBIdentity

public struct ReleaseToken: Equatable, Sendable, CanonicalJSONEncodable, Codable {
    public let serial: TokenSerial
    public let flightID: FlightID
    public let crewID: CrewID
    public let seat: Seat
    public let deviceID: DeviceID
    /// 允许使用的时间窗（以航班计划时刻为中心，由公司下发）。
    public let validFromEpoch: Double
    public let validUntilEpoch: Double
    /// 令牌签发者（公司放行系统）。
    public let issuerID: String
    public let issuerPublicKeyX963: Data
    /// 令牌种类：起飞放行 / 补充放行 / 性能更改。
    public let purpose: ReleasePurpose
    public let envelope: SignatureEnvelope

    public init(
        serial: TokenSerial,
        flightID: FlightID,
        crewID: CrewID,
        seat: Seat,
        deviceID: DeviceID,
        validFromEpoch: Double,
        validUntilEpoch: Double,
        issuerID: String,
        issuerPublicKeyX963: Data,
        purpose: ReleasePurpose,
        envelope: SignatureEnvelope
    ) {
        self.serial = serial
        self.flightID = flightID
        self.crewID = crewID
        self.seat = seat
        self.deviceID = deviceID
        self.validFromEpoch = validFromEpoch
        self.validUntilEpoch = validUntilEpoch
        self.issuerID = issuerID
        self.issuerPublicKeyX963 = issuerPublicKeyX963
        self.purpose = purpose
        self.envelope = envelope
    }

    public var canonicalValue: CanonicalValue {
        .object([
            "crewID": .string(crewID.rawValue),
            "deviceID": .string(deviceID.rawValue),
            "envelope": envelope.canonicalValue,
            "flightID": .string(flightID.rawValue),
            "issuerID": .string(issuerID),
            "issuerPublicKeyX963": .string(issuerPublicKeyX963.base64EncodedString()),
            "purpose": .string(purpose.rawValue),
            "seat": .string(seat.rawValue),
            "serial": .string(serial.rawValue),
            "validFromEpoch": .int(Int(validFromEpoch)),
            "validUntilEpoch": .int(Int(validUntilEpoch)),
        ])
    }

    /// 被签名的内容（不含信封自身）。
    public var signedContent: CanonicalValue {
        .object([
            "crewID": .string(crewID.rawValue),
            "deviceID": .string(deviceID.rawValue),
            "flightID": .string(flightID.rawValue),
            "issuerID": .string(issuerID),
            "issuerPublicKeyX963": .string(issuerPublicKeyX963.base64EncodedString()),
            "purpose": .string(purpose.rawValue),
            "seat": .string(seat.rawValue),
            "serial": .string(serial.rawValue),
            "validFromEpoch": .int(Int(validFromEpoch)),
            "validUntilEpoch": .int(Int(validUntilEpoch)),
            "version": .string("EFB-RELEASE-TOKEN-V1"),
        ])
    }

    /// 离线自检：签名有效 + 时间窗内 + 绑定字段一致。
    public func verifyOffline(
        anchor: TrustAnchor,
        flight: FlightID,
        crew: CrewID,
        seat: Seat,
        device: DeviceID,
        at epoch: Double,
        purpose expected: ReleasePurpose
    ) -> Bool {
        guard envelope.verify(over: signedContent, publicKeyX963: issuerPublicKeyX963) else { return false }
        guard flightID == flight, crewID == crew, self.seat == seat, deviceID == device, purpose == expected else { return false }
        return epoch >= validFromEpoch && epoch <= validUntilEpoch
    }
}

public enum ReleasePurpose: String, Codable, Sendable, CaseIterable {
    case departure = "DEPARTURE"        // 起飞放行
    case performanceAmendment = "PERF_AMEND" // 性能更改
    case supplement = "SUPPLEMENT"      // 补充放行（如加油后重新计算）

    public var displayName: String {
        switch self {
        case .departure: return "起飞放行"
        case .performanceAmendment: return "性能更改放行"
        case .supplement: return "补充放行"
        }
    }
}

/// 令牌库：本机离线持有的、属于本机已预置机组的令牌。
///
/// "已消耗"状态必须持久化：否则应用重启后重新装载同一批令牌，
/// 已用过的序列号会再次可选，导致一签两用（公司端只有在所有记录一起审计时才能发现）。
/// 因此构造时传入 SecureStoring，消耗即落盘。
public final class ReleaseTokenStore: @unchecked Sendable {
    private var tokens: [TokenSerial: ReleaseToken] = [:]
    private var consumed: [TokenSerial: Double] = [:]
    private let lock = NSLock()
    private let store: SecureStoring?
    private static let consumedItem = SecureStoreItem(service: "efb.tokens", account: "consumed")

    public init(store: SecureStoring? = nil) {
        self.store = store
        if let store,
           let persisted = try? store.readCodable([TokenSerial: Double].self, from: Self.consumedItem) {
            consumed = persisted
        }
    }

    public func load(_ list: [ReleaseToken]) throws {
        lock.lock(); defer { lock.unlock() }
        for token in list {
            // 已消耗过的序列号不得被再次装入（防止重启后复活）
            guard consumed[token.serial] == nil else {
                continue
            }
            guard tokens[token.serial] == nil else {
                throw EFBError.tokenInvalid(reason: "重复的令牌序列号 \(token.serial)")
            }
            tokens[token.serial] = token
        }
    }

    public func available(for crew: CrewID, flight: FlightID, seat: Seat, device: DeviceID) -> [ReleaseToken] {
        lock.lock(); defer { lock.unlock() }
        return tokens.values
            .filter { $0.crewID == crew && $0.flightID == flight && $0.seat == seat && $0.deviceID == device }
            .sorted { $0.serial < $1.serial }
    }

    public func isConsumed(_ serial: TokenSerial) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return consumed[serial] != nil
    }

    /// 消耗令牌。必须与签字在同一临界区内完成，防止一签两用。
    public func consume(_ serial: TokenSerial, at epoch: Double) throws -> ReleaseToken {
        lock.lock(); defer { lock.unlock() }
        guard let token = tokens[serial] else {
            throw EFBError.tokenInvalid(reason: "令牌 \(serial) 不在本机")
        }
        guard consumed[serial] == nil else {
            throw EFBError.tokenAlreadyConsumed(serial: serial)
        }
        consumed[serial] = epoch
        if let store {
            try? store.writeCodable(consumed, to: Self.consumedItem)
        }
        return token
    }
}
