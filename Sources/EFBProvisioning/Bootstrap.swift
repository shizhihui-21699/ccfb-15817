// Bootstrap.swift
// 本场预置包：唯一需要网络的步骤。
//
// 信任模型的根**绝不能来自网络**：否则控制那一次预置链路的人（机场开放 Wi-Fi、
// MITM）就能替换根、签发者、锚与令牌，把后面所有"离线核验"都带偏。
//
// 因此：
//   * 公司根公钥编译进应用（TrustAnchor 固定，见 README）；
//   * 预置包本身由该根签名；校验时只信内置根，不接受包里带来的根；
//   * 时间锚与撤销名单也各自被签名，链到内置根。
//
// 这里刻意保持平台无关（不依赖 iOS API），因为公司侧生成预置包时也用同一套结构，
// 且校验逻辑必须可被自动化测试覆盖（CI 不一定有 iPad）。

import Foundation
import EFBCore
import EFBIdentity
import EFBCryptography
import EFBRelease

/// 本场（有网络）从公司系统拉取的预置材料。飞行中不再触网。
public struct BootstrapPackage: Sendable, Codable, CanonicalJSONEncodable {
    public let deviceID: DeviceID
    public let anchor: TimeAnchor
    public let issuers: [IssuerRecord]
    public let revocation: RevocationSnapshot
    public let tokens: [ReleaseToken]
    public let policy: CrewPolicy
    /// 由公司根签名的信封；覆盖上面全部字段（不含自身）。
    public let envelope: SignatureEnvelope

    public init(
        deviceID: DeviceID,
        anchor: TimeAnchor,
        issuers: [IssuerRecord],
        revocation: RevocationSnapshot,
        tokens: [ReleaseToken],
        policy: CrewPolicy,
        envelope: SignatureEnvelope
    ) {
        self.deviceID = deviceID
        self.anchor = anchor
        self.issuers = issuers
        self.revocation = revocation
        self.tokens = tokens
        self.policy = policy
        self.envelope = envelope
    }

    /// 被签名的内容（不含信封自身）。
    public var signedContent: CanonicalValue {
        .object([
            "anchor": anchor.canonicalValue,
            "deviceID": .string(deviceID.rawValue),
            "issuers": .array(issuers.map { $0.signedContent }),
            "policy": policy.canonicalValue,
            "revocation": revocation.signedContent,
            "tokens": .array(tokens.map { $0.signedContent }),
            "version": .string("EFB-BOOTSTRAP-V1"),
        ])
    }

    public var canonicalValue: CanonicalValue {
        .object([
            "envelope": envelope.canonicalValue,
            "signedContent": signedContent,
        ])
    }
}

public enum BootstrapError: Error, Equatable, Sendable {
    case deviceMismatch(expected: DeviceID, actual: DeviceID)
    case anchorInFuture
    case tokenForOtherDevice(TokenSerial)
    case issuerUntrusted(String)
    case packageUnsigned
    case packageSignatureInvalid
    case anchorUnsigned
    case anchorSignatureInvalid
    case rootMismatch
}

/// 校验预置包。这是"设备第一次信任任何东西"的唯一入口，因此**只信内置根**。
public enum BootstrapValidator {
    public static func validate(
        _ package: BootstrapPackage,
        deviceID: DeviceID,
        nowEpoch: Double,
        pinnedAnchor: TrustAnchor,
        pinRootPublicKey: Data
    ) throws {
        // 1) 必须是发给本机的包
        guard package.deviceID == deviceID else {
            throw BootstrapError.deviceMismatch(expected: deviceID, actual: package.deviceID)
        }

        // 2) 预置包本身必须由**内置根**签名（不是包里带来的任何根）
        guard package.envelope.verify(over: package.signedContent, publicKeyX963: pinRootPublicKey),
              package.envelope.signerID == pinnedAnchor.anchorID else {
            throw BootstrapError.packageSignatureInvalid
        }
        try EFBCoreCheck.requireRoot(pinnedAnchor, key: pinRootPublicKey)

        // 3) 锚时间不能大幅超前本地（否则等于把设备时间往前拨）
        guard package.anchor.authoritativeEpoch <= nowEpoch + 3600 else {
            throw BootstrapError.anchorInFuture
        }
        try AnchoredTimeProvider.validate(package.anchor)

        // 4) 签发者必须被内置根签署
        for issuer in package.issuers {
            guard issuer.verify(with: pinnedAnchor, at: nowEpoch) else {
                throw BootstrapError.issuerUntrusted(issuer.issuerID)
            }
        }
        // 5) 撤销名单：签名链到内置根
        guard package.revocation.validUntilEpoch > nowEpoch else {
            throw EFBError.timeAnchorExpired
        }
        guard package.issuers.contains(where: { $0.issuerID == package.revocation.envelope.signerID &&
                                                $0.publicKeyX963 == package.revocation.issuerPublicKeyX963 }),
              package.revocation.verify(with: pinnedAnchor, at: nowEpoch) else {
            throw EFBError.chainUntrusted(reason: "撤销名单签名无效或签发者不在包内")
        }

        // 6) 令牌必须属于本机、且由其签发者（须在包内且已验签）签署
        for token in package.tokens {
            guard token.deviceID == deviceID else {
                throw BootstrapError.tokenForOtherDevice(token.serial)
            }
            guard package.issuers.contains(where: { $0.issuerID == token.issuerID }),
                  token.envelope.verify(over: token.signedContent, publicKeyX963: token.issuerPublicKeyX963) else {
                throw EFBError.tokenInvalid(reason: "令牌 \(token.serial) 的签发者未在预置包内或签名无效")
            }
        }
    }
}

private enum EFBCoreCheck {
    static func requireRoot(_ anchor: TrustAnchor, key: Data) throws {
        guard anchor.publicKeyX963 == key else {
            throw BootstrapError.rootMismatch
        }
    }
}
