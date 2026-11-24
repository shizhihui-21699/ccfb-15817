// KeychainSecureStore.swift
// 安全存储。证书、Secure Enclave 密钥 blob、PIN 校验器都必须落在 Keychain，
// 而不是文件系统 —— 平板可能丢失、被越狱、被取走取证。
//
// 这里只放形状稳定的数据（blob / 证书 / 盐），PIN 明文永不落盘。

import Foundation
import Security
import EFBCore

public struct SecureStoreItem: Sendable {
    public let service: String
    public let account: String
    /// 是否随 iCloud/iTunes 备份迁移。涉及硬件密钥的一律 false。
    public let migratable: Bool

    public init(service: String, account: String, migratable: Bool = false) {
        self.service = service
        self.account = account
        self.migratable = migratable
    }

    var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }
}

public protocol SecureStoring: AnyObject, Sendable {
    func write(_ data: Data, to item: SecureStoreItem) throws
    func read(_ item: SecureStoreItem) throws -> Data?
    func delete(_ item: SecureStoreItem) throws
    func list(service: String) throws -> [String]
}

public extension SecureStoring {
    func writeCodable<T: Encodable>(_ value: T, to item: SecureStoreItem) throws {
        try write(try JSONEncoder().encode(value), to: item)
    }

    func readCodable<T: Decodable>(_ type: T.Type, from item: SecureStoreItem) throws -> T? {
        guard let data = try read(item) else { return nil }
        return try JSONDecoder().decode(type, from: data)
    }
}

public final class KeychainSecureStore: SecureStoring, @unchecked Sendable {
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    public init() {}

    public func write(_ data: Data, to item: SecureStoreItem) throws {
        var query = item.baseQuery
        query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = item.migratable
            ? kSecAttrAccessibleWhenUnlocked
            : kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw EFBError.secureStoreFailure(Int32(status))
        }
    }

    public func read(_ item: SecureStoreItem) throws -> Data? {
        var query = item.baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else {
            throw EFBError.secureStoreFailure(Int32(status))
        }
        return result as? Data
    }

    public func delete(_ item: SecureStoreItem) throws {
        let status = SecItemDelete(item.baseQuery as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw EFBError.secureStoreFailure(Int32(status))
        }
    }

    public func list(service: String) throws -> [String] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess, let items = result as? [[String: Any]] else {
            throw EFBError.secureStoreFailure(Int32(status))
        }
        query.removeAll()
        return items.compactMap { $0[kSecAttrAccount as String] as? String }
    }

    // MARK: 便捷编解码

    public func writeCodable<T: Encodable>(_ value: T, to item: SecureStoreItem) throws {
        let data = try encoder.encode(value)
        try write(data, to: item)
    }

    public func readCodable<T: Decodable>(_ type: T.Type, from item: SecureStoreItem) throws -> T? {
        guard let data = try read(item) else { return nil }
        return try decoder.decode(type, from: data)
    }
}

/// 内存实现（单元测试用），行为与 Keychain 版本一致，但不触达系统。
public final class InMemorySecureStore: SecureStoring, @unchecked Sendable {
    private var storage: [String: Data] = [:]
    private let lock = NSLock()
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    public init() {}

    private func key(_ item: SecureStoreItem) -> String { "\(item.service)|\(item.account)" }

    public func write(_ data: Data, to item: SecureStoreItem) throws {
        lock.lock(); defer { lock.unlock() }
        storage[key(item)] = data
    }

    public func read(_ item: SecureStoreItem) throws -> Data? {
        lock.lock(); defer { lock.unlock() }
        return storage[key(item)]
    }

    public func delete(_ item: SecureStoreItem) throws {
        lock.lock(); defer { lock.unlock() }
        storage[key(item)] = nil
    }

    public func list(service: String) throws -> [String] {
        lock.lock(); defer { lock.unlock() }
        let prefix = "\(service)|"
        return storage.keys.filter { $0.hasPrefix(prefix) }.map { String($0.dropFirst(prefix.count)) }.sorted()
    }

    public func writeCodable<T: Encodable>(_ value: T, to item: SecureStoreItem) throws {
        try write(encoder.encode(value), to: item)
    }

    public func readCodable<T: Decodable>(_ type: T.Type, from item: SecureStoreItem) throws -> T? {
        guard let data = try read(item) else { return nil }
        return try decoder.decode(type, from: data)
    }
}
