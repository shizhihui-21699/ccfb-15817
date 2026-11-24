// IOSPlatform.swift
// iPad 生产环境的平台适配：真实 Secure Enclave、Face ID、Keychain 的自检。
//
// 本文件只在 iOS 目标编译（iOS 16+）。平台无关的装配层（CockpitApp）
// 位于 EFBProvisioning/CockpitApp.swift，因此可在 macOS 上测试。

#if os(iOS)

import Foundation
import CryptoKit
import LocalAuthentication
import EFBCore
import EFBCryptography

// MARK: - 启动时自检

public enum IOSPlatformCapabilities {
    public struct Report: Sendable {
        public let secureEnclaveAvailable: Bool
        public let biometryType: LABiometryType
        public let canUseBiometrics: Bool
        public let canUseDevicePasscode: Bool
        public var supportsTwoFactor: Bool {
            secureEnclaveAvailable && (canUseBiometrics || canUseDevicePasscode)
        }
    }

    /// 应用启动时调用；若任一关键能力缺失，应拒绝进入签字流程。
    public static func inspect() -> Report {
        let context = LAContext()
        let canBiometrics = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        let canPasscode = context.canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
        return Report(
            secureEnclaveAvailable: SecureEnclave.isAvailable,
            biometryType: context.biometryType,
            canUseBiometrics: canBiometrics,
            canUseDevicePasscode: canPasscode
        )
    }
}

#endif
