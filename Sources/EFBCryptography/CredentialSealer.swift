// CredentialSealer.swift
// 用 Secure Enclave 的 P-256 KeyAgreement 密钥派生密钥，把 "凭据密封件" 加密后落盘。
//
// 目的：把 PIN 的 PBKDF2 派生值、证书、审计头等绑到这台设备的这颗芯片上。
// 即便 Keychain 条目被整体拷走（越狱 / 备份泄漏），换一台设备也解不开，
// 因为 SE 私钥不可导出、不可迁移。
//
// 封装格式：ECDH(SE 密钥, 每凭据一次性 ECDH 密钥) -> HKDF-SHA256 -> AES-GCM。
// 密文里带上一次性公钥，解密时用 SE 私钥重现共享密钥。

import Foundation
import CryptoKit
import EFBCore

public struct SealedBox: Equatable, Sendable, Codable {
    /// 一次性 ECDH 公钥（X9.63）。
    public let ephemeralPublicKeyX963: Data
    /// AES-GCM 组合表示（nonce + ciphertext + tag）。
    public let ciphertext: Data

    public init(ephemeralPublicKeyX963: Data, ciphertext: Data) {
        self.ephemeralPublicKeyX963 = ephemeralPublicKeyX963
        self.ciphertext = ciphertext
    }
}

public protocol SealingKey: Sendable {
    var sealingPublicKeyX963: Data { get }
    func open(_ box: SealedBox) throws -> Data
}

/// 基于 Secure Enclave KeyAgreement 的密封密钥。
public final class SecureEnclaveSealingKey: SealingKey, @unchecked Sendable {
    private let blob: Data

    public init(blob: Data) {
        self.blob = blob
    }

    public static func generate() throws -> SecureEnclaveSealingKey {
        guard SecureEnclave.isAvailable else {
            throw EFBError.keyUnavailable(reason: "本设备不支持 Secure Enclave")
        }
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey()
        return SecureEnclaveSealingKey(blob: key.dataRepresentation)
    }

    private func privateKey() throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
        do {
            return try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob)
        } catch {
            throw EFBError.keyUnavailable(reason: "恢复密封密钥失败：\(error)")
        }
    }

    public var sealingPublicKeyX963: Data {
        (try? privateKey().publicKey.x963Representation) ?? Data()
    }

    public var dataRepresentation: Data { blob }

    public func open(_ box: SealedBox) throws -> Data {
        guard let ephemeral = try? P256.KeyAgreement.PublicKey(x963Representation: box.ephemeralPublicKeyX963),
              let sealed = try? AES.GCM.SealedBox(combined: box.ciphertext) else {
            throw EFBError.malformedEncoding(field: "SealedBox")
        }
        let key = try privateKey()
        let secret = try key.sharedSecretFromKeyAgreement(with: ephemeral)
        let symmetric = secret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: Data("EFB-credential-seal-v1".utf8),
            outputByteCount: 32
        )
        do {
            return try AES.GCM.open(sealed, using: symmetric)
        } catch {
            throw EFBError.keyUnavailable(reason: "解封失败（可能密钥不属于本设备）：\(error)")
        }
    }
}

public enum CredentialSealer {
    /// 用给定密封公钥密封数据。可在任意设备上执行（公司下发凭据时也能做）。
    public static func seal(_ plaintext: Data, to sealingPublicKeyX963: Data) throws -> SealedBox {
        guard let publicKey = try? P256.KeyAgreement.PublicKey(x963Representation: sealingPublicKeyX963) else {
            throw EFBError.keyBindingMismatch(reason: "密封公钥格式错误")
        }
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let secret = try ephemeral.sharedSecretFromKeyAgreement(with: publicKey)
        let symmetric = secret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: Data("EFB-credential-seal-v1".utf8),
            outputByteCount: 32
        )
        let sealed = try AES.GCM.seal(plaintext, using: symmetric)
        guard let combined = sealed.combined else {
            throw EFBError.internalError("AES-GCM 组合输出缺失")
        }
        return SealedBox(
            ephemeralPublicKeyX963: ephemeral.publicKey.x963Representation,
            ciphertext: combined
        )
    }

    /// 测试用：软件密封密钥（无 SE 设备降级）。
    public static func seal(_ plaintext: Data, with key: SoftwareSealingKey) throws -> SealedBox {
        try seal(plaintext, to: key.sealingPublicKeyX963)
    }
}

/// 测试 / 无 SE 设备的降级实现。
public final class SoftwareSealingKey: SealingKey, @unchecked Sendable {
    private let privateKey: P256.KeyAgreement.PrivateKey

    public init() {
        self.privateKey = P256.KeyAgreement.PrivateKey()
    }

    public init(rawPrivateKey: Data) throws {
        self.privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: rawPrivateKey)
    }

    public var sealingPublicKeyX963: Data { privateKey.publicKey.x963Representation }

    public var rawPrivateKey: Data { privateKey.rawRepresentation }

    public func open(_ box: SealedBox) throws -> Data {
        guard let ephemeral = try? P256.KeyAgreement.PublicKey(x963Representation: box.ephemeralPublicKeyX963),
              let sealed = try? AES.GCM.SealedBox(combined: box.ciphertext) else {
            throw EFBError.malformedEncoding(field: "SealedBox")
        }
        let secret = try privateKey.sharedSecretFromKeyAgreement(with: ephemeral)
        let symmetric = secret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: Data("EFB-credential-seal-v1".utf8),
            outputByteCount: 32
        )
        return try AES.GCM.open(sealed, using: symmetric)
    }
}
