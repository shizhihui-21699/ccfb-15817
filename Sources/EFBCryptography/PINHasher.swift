// PINHasher.swift
// PIN 校验器：PBKDF2-HMAC-SHA256，盐与迭代次数随凭据一起存储。
//
// PIN 只有 6–8 位，离线暴力空间有限，所以：
//   * 迭代次数取设备当年可承受的上限（默认 120k，可按机型下发）；
//   * 连续错误由 PINAttemptTracker 在本地 + 凭据上计数，锁定后不依赖联网；
//   * 派生值用 Secure Enclave 派生的密钥封存（见 CredentialSealer），即便 Keychain 被整体拷走，
//     没有 SE 也解不开。

import Foundation
import CommonCrypto
import CryptoKit
import EFBCore

public struct PINVerifier: Equatable, Sendable, Codable {
    public let algorithm: String
    public let iterations: Int
    public let salt: Data
    public let derived: Data
    /// PIN 位数（用于判断输入长度与策略）。
    public let digits: Int

    public init(algorithm: String = "PBKDF2-HMAC-SHA256", iterations: Int, salt: Data, derived: Data, digits: Int) {
        self.algorithm = algorithm
        self.iterations = iterations
        self.salt = salt
        self.derived = derived
        self.digits = digits
    }
}

public enum PINHasher {
    public static let defaultIterations = 120_000

    /// 生成新校验器。
    public static func makeVerifier(
        pin: SecureBytes,
        digits: Int,
        salt: Data? = nil,
        iterations: Int = defaultIterations
    ) throws -> PINVerifier {
        // 这里只做存储层的合理性检查；PIN 的长度 / 复杂度策略由 PINAttemptTracker.validatePolicy 负责。
        // 允许更长输入，是因为同一个校验器基元也用于包裹 32 字节的解锁密钥。
        guard digits >= 1, digits <= 64 else {
            throw EFBError.pinPolicyViolation(["凭据长度必须在 1–64 之间"])
        }
        let saltValue = salt ?? Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let derived = try derive(pin: pin, salt: saltValue, iterations: iterations)
        return PINVerifier(iterations: iterations, salt: saltValue, derived: derived, digits: digits)
    }

    /// 常量时间比对。比较前先派生，保证耗时与正确 PIN 一致。
    public static func verify(pin: SecureBytes, against verifier: PINVerifier) throws -> Bool {
        guard pin.count >= 4 else { return false }
        let candidate = try derive(pin: pin, salt: verifier.salt, iterations: verifier.iterations)
        return SecureBytes.constantTimeEquals(SecureBytes(candidate), SecureBytes(verifier.derived))
    }

    public static func derive(
        pin: SecureBytes, salt: Data, iterations: Int, enforceMinimumLength: Bool = true
    ) throws -> Data {
        if enforceMinimumLength {
            guard pin.count >= 4 else {
                throw EFBError.pinPolicyViolation(["PIN 至少 4 位"])
            }
        }
        guard !salt.isEmpty else {
            throw EFBError.malformedEncoding(field: "PINVerifier.salt")
        }
        let saltBytes = salt
        let pinData = pin.data
        var derived = Data(count: 32)
        let status = derived.withUnsafeMutableBytes { out -> Int32 in
            pinData.withUnsafeBytes { pinBytes -> Int32 in
                saltBytes.withUnsafeBytes { saltPtr -> Int32 in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        pinBytes.baseAddress?.assumingMemoryBound(to: CChar.self),
                        pinData.count,
                        saltPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        saltBytes.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        UInt32(iterations),
                        out.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        32
                    )
                }
            }
        }
        guard status == kCCSuccess else {
            throw EFBError.internalError("PBKDF2 失败：\(status)")
        }
        return derived
    }
}

/// 用 PIN 派生密钥包裹 / 解包"解锁密钥"。
///
/// 解锁密钥是随机的 32 字节，用于解开硬件签字密钥（SE 的 applicationPassword）。
/// PIN 只在这一层出现：改 PIN 时重新包裹即可，硬件密钥与证书都不变。
public enum PINWrap {
    private static let info = Data("EFB-pin-wrap-v1".utf8)

    private static func deriveWrappingKey(secret: SecureBytes, salt: Data, iterations: Int) throws -> SymmetricKey {
        // 这里刻意用 "任意秘密" 的派生（不套 PIN 位数策略）：调用方既可能是 6 位 PIN，
        // 也可能是 32 字节解锁密钥。
        let raw = try PINHasher.derive(pin: secret, salt: salt, iterations: iterations, enforceMinimumLength: false)
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: raw),
            salt: Data(),
            info: info,
            outputByteCount: 32
        )
    }

    /// 返回 (salt, iterations, wrappedBlob)。wrappedBlob = AES-GCM 组合表示。
    public static func wrap(
        _ secret: SecureBytes,
        with pin: SecureBytes,
        salt: Data? = nil,
        iterations: Int = 40_000
    ) throws -> (salt: Data, iterations: Int, wrapped: Data) {
        let saltValue = salt ?? Data((0..<24).map { _ in UInt8.random(in: 0...255) })
        let key = try deriveWrappingKey(secret: pin, salt: saltValue, iterations: iterations)
        let sealed = try AES.GCM.seal(secret.data, using: key)
        guard let combined = sealed.combined else {
            throw EFBError.internalError("AES-GCM 组合输出缺失")
        }
        return (saltValue, iterations, combined)
    }

    /// 解包；PIN 错误时抛出 pinIncorrect。
    public static func unwrap(
        _ wrapped: Data,
        pin: SecureBytes,
        salt: Data,
        iterations: Int
    ) throws -> SecureBytes {
        guard let box = try? AES.GCM.SealedBox(combined: wrapped) else {
            throw EFBError.malformedEncoding(field: "wrappedSigningSecret")
        }
        let key = try deriveWrappingKey(secret: pin, salt: salt, iterations: iterations)
        do {
            let opened = try AES.GCM.open(box, using: key)
            return SecureBytes(opened)
        } catch {
            throw EFBError.pinIncorrect(attemptsRemaining: 1)
        }
    }
}
