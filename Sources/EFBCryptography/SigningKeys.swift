// SigningKeys.swift
// 签字密钥的抽象、Secure Enclave 实现，以及可注入的密钥保管库（vault）。
//
// 生产：
//   * 密钥在 Secure Enclave 内生成，私钥无法导出（实测 SecKeyCopyExternalRepresentation
//     对 SE 私钥返回 errSecUnimplemented）；
//   * 密钥 ACL 含 .applicationPassword，也就是每位机组各自的 PIN；
//   * 会话开始时用个人信息解开一次，`lock()` 立即作废，交接后必须重新输 PIN。
//
// 测试 / 无 SE 设备：
//   * SoftwareKeyVault 生成不可导出的软件密钥（仅以内部标识对外），
//     并同样实现 PIN 门禁与 lock() 语义，这样协议测试走的是与生产完全相同的路径；
//   * 真实 Secure Enclave 的生成 / 签名 / 验签由独立测试覆盖（ACL 不含
//     applicationPassword，避免 headless 环境下弹系统 UI）。

import Foundation
import CryptoKit
import Security
import LocalAuthentication
import EFBCore

public enum KeyProtection: String, Equatable, Sendable, Codable {
    case hardwareOnly = "HARDWARE_ONLY"
    case applicationPassword = "APPLICATION_PASSWORD"
    case userPresence = "USER_PRESENCE"
    case userPresenceOrPassword = "USER_PRESENCE_OR_PASSWORD"
}

/// 一次值班会话期间可用的签名句柄。
public protocol SigningKeyHandle: Sendable {
    /// X9.63 表示的公钥（P-256，65 字节）。
    var publicKeyX963: Data { get }
    var protection: KeyProtection { get }
    /// 私钥是否驻留在硬件安全区（SE 为 true；软件降级为 false，公司端据此降级置信度）。
    var isHardwareBacked: Bool { get }
    /// 当前是否已解开 PIN 门禁。
    var isUnlocked: Bool { get }
    /// 会话开始：用一个随机解锁密钥解开（该密钥由凭据密封件保存，PIN 负责解封它）。
    /// 这样 PIN 与硬件密钥解耦：改 PIN 只需重新密封解锁密钥，证书与公钥不变。
    func unlock(withSecret secret: SecureBytes, reason: String) throws
    /// 会话结束 / 交接 / 锁屏：立即作废门禁。
    func lock()
    /// 对数据进行 ECDSA-SHA256 签名，返回 DER。
    func sign(_ data: Data, reason: String) throws -> Data
}

// MARK: - 验签（与密钥实现无关）

public enum SignatureVerifier {
    public static func verify(signatureDER: Data, data: Data, publicKeyX963: Data) -> Bool {
        guard let publicKey = try? P256.Signing.PublicKey(x963Representation: publicKeyX963),
              let signature = try? P256.Signing.ECDSASignature(derRepresentation: signatureDER) else {
            return false
        }
        return publicKey.isValidSignature(signature, for: data)
    }

    /// 直接对 SHA-256 摘要验签（验签方只持有摘要的场景）。
    public static func verify(signatureDER: Data, digest: Data, publicKeyX963: Data) -> Bool {
        guard digest.count == 32 else { return false }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(publicKeyX963 as CFData, attributes as CFDictionary, &error) else {
            return false
        }
        return SecKeyVerifySignature(
            key, .ecdsaSignatureDigestX962SHA256, digest as CFData, signatureDER as CFData, &error
        )
    }
}

// MARK: - Secure Enclave 实现

public final class SecureEnclaveSigningKey: SigningKeyHandle, @unchecked Sendable {
    private let blob: Data
    private let keyProtection: KeyProtection
    private let mutex = NSLock()
    private var sessionContext: LAContext?

    private init(blob: Data, protection: KeyProtection) {
        self.blob = blob
        self.keyProtection = protection
    }

    public static var isAvailable: Bool { SecureEnclave.isAvailable }

    /// 直接生成（ACL 由 protection 决定）。`.applicationPassword` 在生产环境中会要求
    /// 先提供解锁密钥；headless 测试请改用 SoftwareKeyVault 或 hardwareOnly。
    public static func generate(
        protection: KeyProtection = .hardwareOnly,
        secret: SecureBytes? = nil
    ) throws -> SecureEnclaveSigningKey {
        guard SecureEnclave.isAvailable else {
            throw EFBError.keyUnavailable(reason: "本设备不支持 Secure Enclave")
        }
        guard let accessControl = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, accessControlFlags(for: protection), nil
        ) else {
            throw EFBError.keyUnavailable(reason: "无法创建访问控制")
        }
        let context = LAContext()
        context.localizedReason = "为机组成员创建签字密钥"
        if let secret, protection == .applicationPassword {
            context.setCredential(secret.data, type: .applicationPassword)
        }
        do {
            let key = try SecureEnclave.P256.Signing.PrivateKey(
                accessControl: accessControl,
                authenticationContext: context
            )
            return SecureEnclaveSigningKey(blob: key.dataRepresentation, protection: protection)
        } catch {
            throw EFBError.keyUnavailable(reason: "Secure Enclave 生成失败：\(error)")
        }
    }

    public static func restore(blob: Data, protection: KeyProtection) -> SecureEnclaveSigningKey {
        SecureEnclaveSigningKey(blob: blob, protection: protection)
    }

    public var dataRepresentation: Data { blob }

    public var protection: KeyProtection { keyProtection }

    public var isHardwareBacked: Bool { true }

    public var isUnlocked: Bool {
        mutex.lock(); defer { mutex.unlock() }
        return sessionContext != nil
    }

    public func unlock(withSecret secret: SecureBytes, reason: String) throws {
        let context = LAContext()
        context.localizedReason = reason
        context.localizedFallbackTitle = "输入机组 PIN"
        context.localizedCancelTitle = "取消"
        context.setCredential(secret.data, type: .applicationPassword)
        do {
            _ = try SecureEnclave.P256.Signing.PrivateKey(
                dataRepresentation: blob,
                authenticationContext: context
            )
        } catch {
            throw EFBError.pinIncorrect(attemptsRemaining: 1)
        }
        mutex.lock()
        sessionContext?.invalidate()
        sessionContext = context
        mutex.unlock()
    }

    public func lock() {
        mutex.lock()
        sessionContext?.invalidate()
        sessionContext = nil
        mutex.unlock()
    }

    public var publicKeyX963: Data {
        let context = LAContext()
        context.localizedReason = "读取签字公钥"
        guard let key = try? SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: blob,
            authenticationContext: context
        ) else {
            return Data()
        }
        return key.publicKey.x963Representation
    }

    public func sign(_ data: Data, reason: String) throws -> Data {
        guard SecureEnclave.isAvailable else {
            throw EFBError.keyUnavailable(reason: "本设备不支持 Secure Enclave")
        }
        mutex.lock()
        let context = sessionContext
        mutex.unlock()
        guard let context else {
            throw EFBError.keyUnavailable(reason: "签字密钥未解锁，请先输入 PIN")
        }
        do {
            let key = try SecureEnclave.P256.Signing.PrivateKey(
                dataRepresentation: blob,
                authenticationContext: context
            )
            return try key.signature(for: data).derRepresentation
        } catch {
            throw EFBError.signatureInvalid(reason: "Secure Enclave 签名失败：\(error)")
        }
    }

    static func accessControlFlags(for protection: KeyProtection) -> SecAccessControlCreateFlags {
        switch protection {
        case .hardwareOnly: return [.privateKeyUsage]
        case .applicationPassword: return [.privateKeyUsage, .applicationPassword]
        case .userPresence: return [.privateKeyUsage, .userPresence]
        case .userPresenceOrPassword: return [.privateKeyUsage, .userPresence, .or, .applicationPassword]
        }
    }
}

// MARK: - 保管库（可注入）

/// 密钥保管库：生成与恢复签字密钥。
///
/// 之所以要注入：平板的生产实现用 Secure Enclave；CI / 演示机上无法在 headless
/// 环境触发 PIN 系统 UI，于是改用软件保管库，但协议路径（解锁、锁定、签字、交接后失败）
/// 完全一致。
public protocol SigningKeyVault: Sendable {
    /// 该保管库是否提供硬件绑定私钥。
    var isHardwareBacked: Bool { get }
    /// 生成新密钥，返回句柄与可持久化的封存 blob（blob 本身不包含可导出的私钥）。
    /// - Parameter secret: 随机解锁密钥，由凭据密封件保存；PIN 只负责解出它。
    func generate(secret: SecureBytes) throws -> (handle: SigningKeyHandle, blob: Data)
    /// 从 blob 恢复句柄（恢复后为锁定状态）。
    func restore(blob: Data, protection: KeyProtection) throws -> SigningKeyHandle
}

public struct SecureEnclaveKeyVault: SigningKeyVault {
    public init() {}

    public var isHardwareBacked: Bool { SecureEnclave.isAvailable }

    public func generate(secret: SecureBytes) throws -> (handle: SigningKeyHandle, blob: Data) {
        let key = try SecureEnclaveSigningKey.generate(protection: .applicationPassword, secret: secret)
        return (key, key.dataRepresentation)
    }

    public func restore(blob: Data, protection: KeyProtection) throws -> SigningKeyHandle {
        SecureEnclaveSigningKey.restore(blob: blob, protection: protection)
    }
}

/// 软件保管库（测试 / 无 SE 设备的降级）。
///
/// 私钥只保存在保管库内存里，对外只给一个 opaque 标识，API 层面同样无法导出。
/// 它实现与 SE 等价的 PIN 门禁与 lock() 语义。
public final class SoftwareKeyVault: SigningKeyVault, @unchecked Sendable {
    private var keys: [Data: P256.Signing.PrivateKey] = [:]
    /// 每个密钥的 PIN 校验器（派生值，不存明文）。
    private var pinChecks: [Data: PINVerifier] = [:]
    private let mutex = NSLock()

    public init() {}

    public var isHardwareBacked: Bool { false }

    public func generate(secret: SecureBytes) throws -> (handle: SigningKeyHandle, blob: Data) {
        let privateKey = P256.Signing.PrivateKey()
        let identifier = Data(SHA256.hash(data: privateKey.publicKey.x963Representation + UUID().uuidString.data(using: .utf8)!))
        let verifier = try PINHasher.makeVerifier(pin: secret, digits: secret.count, iterations: 12_000)
        mutex.lock()
        keys[identifier] = privateKey
        pinChecks[identifier] = verifier
        mutex.unlock()
        let handle = SoftwareKeyHandle(identifier: identifier, vault: self)
        return (handle, identifier)
    }

    public func restore(blob: Data, protection: KeyProtection) throws -> SigningKeyHandle {
        mutex.lock()
        let exists = keys[blob] != nil
        mutex.unlock()
        guard exists else {
            throw EFBError.keyUnavailable(reason: "软件密钥 \(blob.prefix(8)) 不存在")
        }
        return SoftwareKeyHandle(identifier: blob, vault: self)
    }

    fileprivate func privateKey(for identifier: Data) -> P256.Signing.PrivateKey? {
        mutex.lock(); defer { mutex.unlock() }
        return keys[identifier]
    }

    fileprivate func checkSecret(_ secret: SecureBytes, for identifier: Data) -> Bool {
        mutex.lock()
        let verifier = pinChecks[identifier]
        mutex.unlock()
        guard let verifier else { return false }
        return (try? PINHasher.verify(pin: secret, against: verifier)) ?? false
    }
}

private final class SoftwareKeyHandle: SigningKeyHandle, @unchecked Sendable {
    let identifier: Data
    unowned let vault: SoftwareKeyVault
    private let mutex = NSLock()
    private var unlocked = false

    init(identifier: Data, vault: SoftwareKeyVault) {
        self.identifier = identifier
        self.vault = vault
    }

    var publicKeyX963: Data {
        vault.privateKey(for: identifier)?.publicKey.x963Representation ?? Data()
    }

    var protection: KeyProtection { .applicationPassword }

    var isHardwareBacked: Bool { false }

    var isUnlocked: Bool {
        mutex.lock(); defer { mutex.unlock() }
        return unlocked
    }

    func unlock(withSecret secret: SecureBytes, reason: String) throws {
        guard vault.checkSecret(secret, for: identifier) else {
            throw EFBError.keyUnavailable(reason: "解锁密钥不匹配")
        }
        mutex.lock()
        unlocked = true
        mutex.unlock()
    }

    func lock() {
        mutex.lock()
        unlocked = false
        mutex.unlock()
    }

    func sign(_ data: Data, reason: String) throws -> Data {
        mutex.lock()
        let ready = unlocked
        mutex.unlock()
        guard ready, let key = vault.privateKey(for: identifier) else {
            throw EFBError.keyUnavailable(reason: "签字密钥未解锁")
        }
        return try key.signature(for: data).derRepresentation
    }
}

// MARK: - 无门禁软件密钥（仅供根/签发者使用）

/// 公司根 / 签发者用的内存密钥（公司侧工具），不面向机组。
public final class SoftwareSigningKey: @unchecked Sendable {
    private let privateKey: P256.Signing.PrivateKey

    public init() {
        self.privateKey = P256.Signing.PrivateKey()
    }

    public init(rawPrivateKey: Data) throws {
        self.privateKey = try P256.Signing.PrivateKey(rawRepresentation: rawPrivateKey)
    }

    public var publicKeyX963: Data { privateKey.publicKey.x963Representation }

    public var rawPrivateKey: Data { privateKey.rawRepresentation }

    public func sign(_ data: Data, reason: String) throws -> Data {
        try privateKey.signature(for: data).derRepresentation
    }
}
