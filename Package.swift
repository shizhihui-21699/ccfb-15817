// swift-tools-version: 6.0
import PackageDescription

// EFBCrewIdentity
//
// 面向驾驶舱共享平板的机组身份核验 / 会话交接 / 双人放行签字库。
//
// 设计目标（全部离线可完成）：
//   * 签字必须具备三因素：知道（PIN）/ 持有（SE 硬件密钥或机组徽章）+ 现场生物识别；
//   * 一次放行必须由机长与副驾驶两名不同机组成员分别签字，且一人不能签两角；
//   * 会话交接必须显式、可审计，上一人的登录状态在签字后立刻销毁；
//   * 离线签字在落地后由公司用公开材料（CA 根、证书、令牌清单）核验为本人所为。
//
// 语言模式使用 v5：核心库是同步、单线程编排的（界面层负责串行化），
// 避免为了满足严格并发检查而给 Secure Enclave 句柄套上不必要的 actor 边界。
let package = Package(
    name: "EFBCrewIdentity",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: [
        .library(name: "EFBCore", targets: ["EFBCore"]),
        .library(name: "EFBCryptography", targets: ["EFBCryptography"]),
        .library(name: "EFBIdentity", targets: ["EFBIdentity"]),
        .library(name: "EFBRelease", targets: ["EFBRelease"]),
        .library(name: "EFBSession", targets: ["EFBSession"]),
        // 公司侧签发 / 审计工具：绝不应编译进平板应用。
        .library(name: "EFBProvisioning", targets: ["EFBProvisioning"]),
        .library(name: "EFBCompany", targets: ["EFBCompany"]),
        .executable(name: "efbdemo", targets: ["efbdemo"]),
        .executable(name: "efbverify", targets: ["efbverify"]),
    ],
    targets: [
        .target(name: "EFBCore"),
        .target(name: "EFBCryptography", dependencies: ["EFBCore"]),
        .target(name: "EFBIdentity", dependencies: ["EFBCore", "EFBCryptography"]),
        .target(name: "EFBRelease", dependencies: ["EFBCore", "EFBCryptography", "EFBIdentity"]),
        // 预置包需要同时引用身份与放行类型，单独成模块以避免 Identity<->Release 循环依赖。
        .target(name: "EFBProvisioning", dependencies: ["EFBCore", "EFBCryptography", "EFBIdentity", "EFBRelease", "EFBSession"]),
        .target(name: "EFBSession", dependencies: ["EFBCore", "EFBCryptography", "EFBIdentity", "EFBRelease"]),
        // 公司侧签发 / 审计工具：绝不应编译进平板应用。
        .target(name: "EFBCompany", dependencies: ["EFBCore", "EFBCryptography", "EFBIdentity", "EFBRelease", "EFBSession", "EFBProvisioning"]),
        .executableTarget(name: "efbverify", dependencies: ["EFBCore", "EFBCryptography", "EFBIdentity", "EFBRelease", "EFBSession", "EFBCompany", "EFBProvisioning"]),
        .executableTarget(name: "efbdemo", dependencies: ["EFBCore", "EFBCryptography", "EFBIdentity", "EFBRelease", "EFBSession", "EFBCompany", "EFBProvisioning"]),
    ],
    swiftLanguageModes: [.v5]
)
