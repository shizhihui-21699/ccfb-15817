// SecureBytes.swift
// 敏感字节的短生命周期容器。
//
// 说明：Swift 值语义无法保证 "overelease" 内存，这里能保证的是：
//   * 容器自身释放时显式清零；
//   * 不提供暴露内容的 description / debugDescription，避免把 PIN 打进日志；
//   * 提供常量时间比较，避免时序侧信道把 PIN 逐位泄漏。
//
// 局限：Data 的写时复制副本仍可能短暂存在。因此 PIN 一旦验证完就销毁，
// 长期保存的只有 PBKDF2 派生值，且它被 Secure Enclave 密钥封存。

import Foundation

public final class SecureBytes: @unchecked Sendable {
    private var storage: [UInt8]
    private let locked = NSLock()

    public init(_ bytes: [UInt8]) {
        self.storage = bytes
    }

    public init(_ data: Data) {
        self.storage = Array(data)
    }

    public var count: Int { storage.count }

    public var isEmpty: Bool { storage.isEmpty }

    /// 只读快照：给需要 Data 的系统 API 用。调用方用完应尽快丢弃。
    public var data: Data { Data(storage) }

    public static func constantTimeEquals(_ lhs: SecureBytes, _ rhs: SecureBytes) -> Bool {
        guard lhs.storage.count == rhs.storage.count else { return false }
        var diff: UInt8 = 0
        for index in 0..<lhs.storage.count {
            diff |= lhs.storage[index] ^ rhs.storage[index]
        }
        return diff == 0
    }

    public func wipe() {
        locked.lock()
        defer { locked.unlock() }
        for index in storage.indices { storage[index] = 0 }
        storage.removeAll(keepingCapacity: false)
    }

    deinit {
        wipe()
    }
}

extension SecureBytes: CustomStringConvertible, CustomDebugStringConvertible {
    public var description: String { "SecureBytes(\(count) bytes, redacted)" }
    public var debugDescription: String { description }
}

/// 让调用方在闭包内使用敏感值，闭包返回后立即清零。
public func withSecureBytes<T>(_ bytes: [UInt8], _ body: (SecureBytes) throws -> T) rethrows -> T {
    let secure = SecureBytes(bytes)
    defer { secure.wipe() }
    return try body(secure)
}
