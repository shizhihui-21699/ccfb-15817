// SessionManager.swift
// 共享平板上的座位会话与交接。
//
// 要解决的两类事故：
//   1. 上一位机长没有登出，下一位机组直接使用其会话签字 —— 追究下来签字属于上一人。
//   2. 有人借用他人账号登录，替对方完成签字。
//
// 对应强制约束：
//   * 每个座位同一时刻最多一个活跃会话（UnlockedCrew）；
//   * 座位已被占用时，新机组不能直接顶替：必须旧会话已结束（主动登出 / 闲置锁定后登出）
//     或持有主管签发的一次性接管授权；
//   * 交接提交的同一刻，旧会话 dispose（SE 密钥门禁立即失效），其 grant 全部作废；
//   * 同一 crewID 不能同时占用两个座位；
//   * 每段 "无人值守空窗"（上一个会话结束 → 下一个会话开始）都被记录为 custody gap。
//
// 空闲锁定：由 UI 上报最近活动时间；超过阈值时只丢弃 SE 门禁（key.lock），
// 会话本身仍在，重新解锁需 PIN。这样即便 app 被切后台、计时器暂停，判定仍然可靠。

import Foundation
import EFBCore
import EFBIdentity
import EFBCryptography

public enum HandoverMethod: String, Codable, Sendable {
    case initialSignIn = "INITIAL_SIGN_IN"
    case inPerson = "IN_PERSON"
    case authorizedTakeover = "AUTHORIZED_TAKEOVER"
    case custodyGapAcknowledged = "CUSTODY_GAP_ACKNOWLEDGED"

    public var displayName: String {
        switch self {
        case .initialSignIn: return "首次登录"
        case .inPerson: return "现场交接"
        case .authorizedTakeover: return "授权接管"
        case .custodyGapAcknowledged: return "空窗确认接管"
        }
    }
}

public struct SeatSession: Sendable {
    public let seat: Seat
    public let crew: UnlockedCrew
    public var lastActivityEpoch: Double
    public var isIdleLocked: Bool

    public var crewID: CrewID { crew.crewID }
}

/// 一段会话结束后的留痕（用于计算下一次登录的无人值守空窗）。
struct ClosedSession: Sendable {
    let crew: CrewID
    let sessionID: SessionID
    let endedAtEpoch: Double
    let endedBySignOut: Bool
}

public struct HandoverRecord: Equatable, Sendable, CanonicalJSONEncodable, Codable {
    public let seat: Seat
    public let fromCrew: CrewID?
    public let fromSessionID: SessionID?
    public let toCrew: CrewID
    public let toSessionID: SessionID
    public let method: HandoverMethod
    public let atEpoch: Double
    /// 上一个会话结束到本次登录之间的空窗（秒）。首次登录为 0。
    public let custodyGapSeconds: Double
    public let authorizationReference: String?

    public init(
        seat: Seat,
        fromCrew: CrewID?,
        fromSessionID: SessionID?,
        toCrew: CrewID,
        toSessionID: SessionID,
        method: HandoverMethod,
        atEpoch: Double,
        custodyGapSeconds: Double,
        authorizationReference: String? = nil
    ) {
        self.seat = seat
        self.fromCrew = fromCrew
        self.fromSessionID = fromSessionID
        self.toCrew = toCrew
        self.toSessionID = toSessionID
        self.method = method
        self.atEpoch = atEpoch
        self.custodyGapSeconds = custodyGapSeconds
        self.authorizationReference = authorizationReference
    }

    public var canonicalValue: CanonicalValue {
        var fields: [String: CanonicalValue] = [
            "atEpoch": .int(Int(atEpoch)),
            "custodyGapSeconds": .int(Int(custodyGapSeconds)),
            "method": .string(method.rawValue),
            "seat": .string(seat.rawValue),
            "toCrew": .string(toCrew.rawValue),
            "toSessionID": .string(toSessionID.rawValue),
        ]
        if let fromCrew { fields["fromCrew"] = .string(fromCrew.rawValue) }
        if let fromSessionID { fields["fromSessionID"] = .string(fromSessionID.rawValue) }
        if let authorizationReference { fields["authorizationReference"] = .string(authorizationReference) }
        return .object(fields)
    }
}

/// 主管签发的接管授权。离线预下发，或经 ACARS / 卫星链路临时下发。
public struct TakeoverAuthorization: Equatable, Sendable, CanonicalJSONEncodable, Codable {
    public let authorizationID: String
    public let deviceID: DeviceID
    public let seat: Seat
    /// 允许接管的目标旧机组；nil 表示任意当前占用者。
    public let subjectCrew: CrewID?
    public let issuedAtEpoch: Double
    public let expiresAtEpoch: Double
    public let issuerID: String
    public let issuerPublicKeyX963: Data
    public let envelope: SignatureEnvelope

    public init(
        authorizationID: String,
        deviceID: DeviceID,
        seat: Seat,
        subjectCrew: CrewID?,
        issuedAtEpoch: Double,
        expiresAtEpoch: Double,
        issuerID: String,
        issuerPublicKeyX963: Data,
        envelope: SignatureEnvelope
    ) {
        self.authorizationID = authorizationID
        self.deviceID = deviceID
        self.seat = seat
        self.subjectCrew = subjectCrew
        self.issuedAtEpoch = issuedAtEpoch
        self.expiresAtEpoch = expiresAtEpoch
        self.issuerID = issuerID
        self.issuerPublicKeyX963 = issuerPublicKeyX963
        self.envelope = envelope
    }

    public var canonicalValue: CanonicalValue {
        var fields: [String: CanonicalValue] = [
            "authorizationID": .string(authorizationID),
            "deviceID": .string(deviceID.rawValue),
            "envelope": envelope.canonicalValue,
            "expiresAtEpoch": .int(Int(expiresAtEpoch)),
            "issuedAtEpoch": .int(Int(issuedAtEpoch)),
            "issuerID": .string(issuerID),
            "issuerPublicKeyX963": .string(issuerPublicKeyX963.base64EncodedString()),
            "seat": .string(seat.rawValue),
        ]
        if let subjectCrew { fields["subjectCrew"] = .string(subjectCrew.rawValue) }
        return .object(fields)
    }

    /// 被签名的内容（不含信封自身）。
    public var signedContent: CanonicalValue {
        var fields: [String: CanonicalValue] = [
            "authorizationID": .string(authorizationID),
            "deviceID": .string(deviceID.rawValue),
            "expiresAtEpoch": .int(Int(expiresAtEpoch)),
            "issuedAtEpoch": .int(Int(issuedAtEpoch)),
            "issuerID": .string(issuerID),
            "issuerPublicKeyX963": .string(issuerPublicKeyX963.base64EncodedString()),
            "seat": .string(seat.rawValue),
            "version": .string("EFB-TAKEOVER-V1"),
        ]
        if let subjectCrew { fields["subjectCrew"] = .string(subjectCrew.rawValue) }
        return .object(fields)
    }

    /// 离线校验（只凭预置的主管公钥）。
    public func verify(trustedIssuerKey: Data, device: DeviceID, seat targetSeat: Seat, occupant: CrewID, at epoch: Double) -> Bool {
        guard trustedIssuerKey == issuerPublicKeyX963 else { return false }
        guard envelope.verify(over: signedContent, publicKeyX963: issuerPublicKeyX963) else { return false }
        guard deviceID == device, seat == targetSeat else { return false }
        guard epoch >= issuedAtEpoch, epoch <= expiresAtEpoch else { return false }
        if let subjectCrew, subjectCrew != occupant { return false }
        return true
    }
}

public final class SessionManager: @unchecked Sendable {
    private let policy: CrewPolicy
    private let time: TrustedTimeProviding
    private let deviceID: DeviceID
    // 递归锁：公开的变更操作在入口整体持锁，内部方法也能安全再次加锁，
    // 从而把"检查座位状态 -> 安装会话 -> 结束旧会话"变成一次原子操作（消除 TOCTOU）。
    private let mutex = NSRecursiveLock()
    private var seats: [Seat: SeatSession] = [:]
    /// 每个座位最近一次结束的会话身份（用于在交接记录里写明 fromCrew）。
    private var lastEnded: [Seat: ClosedSession] = [:]
    private var closed: [Seat: ClosedSession] = [:]
    private var handoverLog: [HandoverRecord] = []
    /// 已使用过的接管授权编号。授权是一次性的，否则一张 2 小时授权
    /// 可以在有效期内反复踢掉同一座位的后续机组。
    private var consumedAuthorizations: Set<String> = []
    private let store: SecureStoring?
    private static let takeoverItem = SecureStoreItem(service: "efb.session", account: "consumed-takeovers")

    public init(policy: CrewPolicy, time: TrustedTimeProviding, deviceID: DeviceID, store: SecureStoring? = nil) {
        self.policy = policy
        self.time = time
        self.deviceID = deviceID
        self.store = store
        if let st = store,
           let persisted = try? st.readCodable([String].self, from: Self.takeoverItem) {
            consumedAuthorizations = Set(persisted)
        }
    }

    private func persistTakeovers() {
        guard let store else { return }
        try? store.writeCodable(Array(consumedAuthorizations), to: Self.takeoverItem)
    }

    // MARK: 查询

    public func occupant(of seat: Seat) -> UnlockedCrew? {
        mutex.lock(); defer { mutex.unlock() }
        return seats[seat]?.crew
    }

    public func session(of seat: Seat) -> SeatSession? {
        mutex.lock(); defer { mutex.unlock() }
        return seats[seat]
    }

    public func activeSeats() -> [Seat] {
        mutex.lock(); defer { mutex.unlock() }
        return seats.keys.sorted { $0.rawValue < $1.rawValue }
    }

    public func seatHeld(by crew: CrewID) -> Seat? {
        mutex.lock(); defer { mutex.unlock() }
        return seats.first { $0.value.crewID == crew }?.key
    }

    public var handovers: [HandoverRecord] {
        mutex.lock(); defer { mutex.unlock() }
        return handoverLog
    }

    /// 当前无人值守空窗（若某座位最后一个会话在过去的 X 秒结束）。
    public func custodyGap(for seat: Seat, at epoch: Double) -> Double? {
        mutex.lock(); defer { mutex.unlock() }
        guard seats[seat] == nil, let last = closed[seat] else { return nil }
        return max(0, epoch - last.endedAtEpoch)
    }

    // MARK: 登录 / 交接

    public func openSession(
        _ crew: UnlockedCrew,
        at seat: Seat,
        takeoverAuthorization: TakeoverAuthorization? = nil,
        trustedTakeoverIssuerKey: Data? = nil,
        acknowledgeCustodyGap: Bool = false,
        audit: inout AuditLog
    ) throws -> HandoverRecord {
        mutex.lock()
        defer { mutex.unlock() }
        let now = try time.currentEpoch()

        // 同一人不能占用两个座位
        if seatHeld(by: crew.crewID) != nil {
            throw EFBError.duplicateCrew(crew.crewID)
        }

        mutex.lock()
        let existing = seats[seat]
        let previous = closed[seat]
        mutex.unlock()

        // 首次登录（该座位从未有过会话）
        guard existing != nil || previous != nil else {
            mutex.lock()
            seats[seat] = SeatSession(seat: seat, crew: crew, lastActivityEpoch: now, isIdleLocked: false)
            mutex.unlock()
            audit.append(kind: .sessionOpened, atEpoch: now, crew: crew.crewID, seat: seat,
                         detail: "session=\(crew.sessionID.rawValue) method=INITIAL_SIGN_IN")
            let record = HandoverRecord(
                seat: seat, fromCrew: nil, fromSessionID: nil,
                toCrew: crew.crewID, toSessionID: crew.sessionID,
                method: .initialSignIn, atEpoch: now, custodyGapSeconds: 0
            )
            appendHandover(record)
            return record
        }

        // 座位上有活跃会话：旧机组必须已经结束会话，或持有一张有效接管授权。
        var method: HandoverMethod
        var gap: Double = 0
        if let existing {
            gap = max(0, now - existing.lastActivityEpoch)

            if existing.crew.isDisposed {
                // 旧会话已被结束（例如锁屏后被主管结束，或对象被外部 dispose）。
                mutex.lock()
                seats[seat] = nil
                mutex.unlock()
                closed[seat] = ClosedSession(crew: existing.crewID, sessionID: existing.crew.sessionID,
                                             endedAtEpoch: existing.lastActivityEpoch, endedBySignOut: true)
                method = gap > policy.custodyGapToleranceSeconds ? .custodyGapAcknowledged : .inPerson
            } else if let authorization = takeoverAuthorization {
                guard let key = trustedTakeoverIssuerKey,
                      authorization.verify(trustedIssuerKey: key, device: deviceID, seat: seat,
                                           occupant: existing.crewID, at: now) else {
                    throw EFBError.handoverIncomplete(reason: "接管授权无效、已过期或不匹配")
                }
                mutex.lock()
                let alreadyUsed = consumedAuthorizations.contains(authorization.authorizationID)
                mutex.unlock()
                guard !alreadyUsed else {
                    throw EFBError.handoverIncomplete(reason: "接管授权 \(authorization.authorizationID) 已被使用")
                }
                method = .authorizedTakeover
            } else {
                throw EFBError.seatOccupied(seat)
            }

            if gap > policy.custodyGapToleranceSeconds && !acknowledgeCustodyGap && method != .authorizedTakeover {
                throw EFBError.custodyGapUnacknowledged(seconds: gap)
            }

            // 提交交接：先废掉旧会话的 PIN 门禁，再登记新会话。
            existing.crew.dispose()
            mutex.lock()
            lastEnded[seat] = ClosedSession(crew: existing.crewID, sessionID: existing.crew.sessionID,
                                            endedAtEpoch: existing.lastActivityEpoch, endedBySignOut: false)
            mutex.unlock()
            audit.append(kind: .handoverBegin, atEpoch: now, crew: crew.crewID, seat: seat,
                         detail: "from=\(existing.crewID) gap=\(Int(gap)) method=\(method.rawValue)")
        } else if let previous {
            // 座位当前空闲，但有上一段会话留痕：愈合空窗并记录。
            gap = max(0, now - previous.endedAtEpoch)
            method = gap > policy.custodyGapToleranceSeconds ? .custodyGapAcknowledged : .inPerson
            if gap > policy.custodyGapToleranceSeconds && !acknowledgeCustodyGap {
                throw EFBError.custodyGapUnacknowledged(seconds: gap)
            }
            mutex.lock()
            lastEnded[seat] = previous
            mutex.unlock()
        } else {
            method = .inPerson
        }

        mutex.lock()
        seats[seat] = SeatSession(seat: seat, crew: crew, lastActivityEpoch: now, isIdleLocked: false)
        closed[seat] = nil
        mutex.unlock()

        if let authorization = takeoverAuthorization, method == .authorizedTakeover {
            mutex.lock()
            consumedAuthorizations.insert(authorization.authorizationID)
            persistTakeovers()
            mutex.unlock()
        }
        audit.append(kind: .handoverCommitted, atEpoch: now, crew: crew.crewID, seat: seat,
                     detail: "to=\(crew.crewID) gap=\(Int(gap))")
        if method == .authorizedTakeover, let authorization = takeoverAuthorization {
            audit.append(kind: .takeoverAuthorized, atEpoch: now, crew: crew.crewID, seat: seat,
                         detail: "auth=\(authorization.authorizationID)")
        }

        mutex.lock()
        let endedCrew = existing?.crewID ?? lastEnded[seat]?.crew
        let endedSession = existing?.crew.sessionID ?? lastEnded[seat]?.sessionID
        mutex.unlock()
        let record = HandoverRecord(
            seat: seat,
            fromCrew: endedCrew,
            fromSessionID: endedSession,
            toCrew: crew.crewID,
            toSessionID: crew.sessionID,
            method: method,
            atEpoch: now,
            custodyGapSeconds: gap,
            authorizationReference: takeoverAuthorization?.authorizationID
        )
        appendHandover(record)
        return record
    }

    // MARK: 登出 / 锁屏

    public func signOut(seat: Seat, audit: inout AuditLog) throws {
        mutex.lock()
        defer { mutex.unlock() }
        let now = try time.currentEpoch()
        mutex.lock()
        let existing = seats.removeValue(forKey: seat)
        mutex.unlock()
        guard let existing else { return }
        existing.crew.dispose()
        mutex.lock()
        closed[seat] = ClosedSession(crew: existing.crewID, sessionID: existing.crew.sessionID,
                                     endedAtEpoch: now, endedBySignOut: true)
        mutex.unlock()
        audit.append(kind: .sessionClosed, atEpoch: now, crew: existing.crewID, seat: seat,
                     detail: "session=\(existing.crew.sessionID.rawValue)")
    }

    /// UI 上报交互，驱动空闲锁定。
    public func recordActivity(seat: Seat, at epoch: Double) {
        mutex.lock(); defer { mutex.unlock() }
        seats[seat]?.lastActivityEpoch = epoch
        seats[seat]?.isIdleLocked = false
    }

    /// 空闲锁定：超过阈值时丢弃 SE 门禁（key.lock），会话保留，重解锁需要 PIN。
    public func lockIdleSessions(at epoch: Double, audit: inout AuditLog) -> [Seat] {
        mutex.lock()
        defer { mutex.unlock() }
        var locked: [Seat] = []
        mutex.lock()
        let snapshot = seats
        mutex.unlock()
        for (seat, session) in snapshot {
            let idle = epoch - session.lastActivityEpoch
            if idle > policy.leaseIdleLockSeconds && !session.isIdleLocked {
                session.crew.signingKey.lock()
                mutex.lock()
                seats[seat]?.isIdleLocked = true
                mutex.unlock()
                audit.append(kind: .sessionLockedIdle, atEpoch: epoch, crew: session.crewID, seat: seat,
                             detail: "idle=\(Int(idle))")
                locked.append(seat)
            }
        }
        return locked.sorted { $0.rawValue < $1.rawValue }
    }

    /// 会话硬租约到期：强制结束并留痕。
    public func expireStaleSessions(at epoch: Double, audit: inout AuditLog) -> [Seat] {
        mutex.lock()
        defer { mutex.unlock() }
        var expired: [Seat] = []
        mutex.lock()
        let snapshot = seats
        mutex.unlock()
        for (seat, session) in snapshot where epoch > session.crew.hardExpiryEpoch {
            session.crew.dispose()
            mutex.lock()
            seats[seat] = nil
            closed[seat] = ClosedSession(crew: session.crewID, sessionID: session.crew.sessionID,
                                         endedAtEpoch: epoch, endedBySignOut: false)
            mutex.unlock()
            audit.append(kind: .sessionClosed, atEpoch: epoch, crew: session.crewID, seat: seat,
                         detail: "reason=lease-expired")
            expired.append(seat)
        }
        return expired.sorted { $0.rawValue < $1.rawValue }
    }

    // MARK: 签字前检查

    /// 本次放行的两名签字人必须各占一个座位，且当前会话就是他们本人的。
    public func verifySignersAreSeated(_ crews: [CrewID]) throws {
        mutex.lock()
        let snapshot = seats
        mutex.unlock()
        for crew in crews {
            guard let pair = snapshot.first(where: { $0.value.crewID == crew }) else {
                throw EFBError.handoverIncomplete(reason: "签字机组 \(crew) 当前没有活跃会话")
            }
            guard !pair.value.crew.isDisposed else {
                throw EFBError.handoverIncomplete(reason: "签字机组 \(crew) 的会话已失效")
            }
        }
        let usedSeats = snapshot.filter { crews.contains($0.value.crewID) }.map(\.key)
        guard Set(usedSeats).count == crews.count else {
            throw EFBError.handoverIncomplete(reason: "两名签字人占用同一座位")
        }
    }

    private func appendHandover(_ record: HandoverRecord) {
        mutex.lock()
        handoverLog.append(record)
        mutex.unlock()
    }
}
