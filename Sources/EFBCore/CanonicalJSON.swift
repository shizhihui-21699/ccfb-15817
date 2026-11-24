// CanonicalJSON.swift
// 离线签名的载荷必须先规范化再签名，否则同一份数据在不同平台/版本上会产出不同字节。
//
// 规则（RFC 8785 的严格子集，只保留本库真正需要的部分）：
//   * 对象键按 UTF-8 字节序（即 ASCII 码点序）升序排列；
//   * 无空白；
//   * 只允许：对象、数组、字符串、布尔、Int64、UInt64；
//   * 整数字面量不带正号、不带小数、不带指数；
//   * 字符串转义仅使用 \" \\ \b \f \n \r \t 与 \u00XX（其余控制字符），
//     非 ASCII 字符按原始 UTF-8 输出，不做 \u 转义；
//   * null 一律省略字段，禁止出现。

import Foundation
import CryptoKit

public enum CanonicalValue: Equatable, Sendable {
    case string(String)
    case int(Int)
    case uint(UInt)
    case bool(Bool)
    case array([CanonicalValue])
    case object([String: CanonicalValue])
}

extension CanonicalValue {
    public var canonicalBytes: Data {
        var out = Data()
        appendCanonical(to: &out)
        return out
    }

    public var canonicalString: String {
        String(decoding: canonicalBytes, as: UTF8.self)
    }

    private func appendCanonical(to out: inout Data) {
        switch self {
        case let .string(value):
            CanonicalWriter.writeString(value, into: &out)
        case let .int(value):
            out.append(contentsOf: Array(String(value).utf8))
        case let .uint(value):
            out.append(contentsOf: Array(String(value).utf8))
        case let .bool(value):
            out.append(contentsOf: Array((value ? "true" : "false").utf8))
        case let .array(values):
            out.append(0x5B) // [
            for (index, value) in values.enumerated() {
                if index > 0 { out.append(0x2C) } // ,
                value.appendCanonical(to: &out)
            }
            out.append(0x5D) // ]
        case let .object(fields):
            out.append(0x7B) // {
            let keys = fields.keys.sorted { lhs, rhs in
                lhs.utf8.lexicographicallyPrecedes(rhs.utf8)
            }
            for (index, key) in keys.enumerated() {
                if index > 0 { out.append(0x2C) }
                CanonicalWriter.writeString(key, into: &out)
                out.append(0x3A) // :
                fields[key]!.appendCanonical(to: &out)
            }
            out.append(0x7D) // }
        }
    }
}

private enum CanonicalWriter {
    static func writeString(_ value: String, into out: inout Data) {
        out.append(0x22) // "
        for scalar in value.unicodeScalars {
            switch scalar {
            case "\"": out.append(contentsOf: Array("\\\"".utf8))
            case "\\": out.append(contentsOf: Array("\\\\".utf8))
            case "\u{08}": out.append(contentsOf: Array("\\b".utf8))
            case "\u{0C}": out.append(contentsOf: Array("\\f".utf8))
            case "\n": out.append(contentsOf: Array("\\n".utf8))
            case "\r": out.append(contentsOf: Array("\\r".utf8))
            case "\t": out.append(contentsOf: Array("\\t".utf8))
            case let c where c.value < 0x20:
                out.append(contentsOf: Array(String(format: "\\u%04x", c.value).utf8))
            default:
                out.append(contentsOf: Array(String(scalar).utf8))
            }
        }
        out.append(0x22)
    }
}

/// 凡是进入签名载荷的类型都实现它。
public protocol CanonicalJSONEncodable {
    var canonicalValue: CanonicalValue { get }
}

extension CanonicalValue: CanonicalJSONEncodable {
    public var canonicalValue: CanonicalValue { self }
}

public extension CanonicalJSONEncodable {
    var canonicalBytes: Data { canonicalValue.canonicalBytes }
    var canonicalString: String { canonicalValue.canonicalString }
    var canonicalSHA256: SHA256Digest { SHA256Digest(hashing: canonicalBytes) }
}

/// 与 CryptoKit 解耦的 32 字节摘要常量，便于在协议层不直接暴露 CryptoKit 类型。
public struct SHA256Digest: Hashable, Sendable, CustomStringConvertible, Codable {
    public let bytes: Data

    public init(bytes: Data) throws {
        guard bytes.count == 32 else { throw EFBError.malformedEncoding(field: "SHA256Digest") }
        self.bytes = bytes
    }

    public init(hashing data: Data) {
        self.bytes = Data(SHA256.hash(data: data))
    }

    public init(hashing value: some CanonicalJSONEncodable) {
        self.bytes = Data(SHA256.hash(data: value.canonicalBytes))
    }

    public var hexString: String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    public var description: String { hexString }

    public static let zero = SHA256Digest(hashing: Data())

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let hex = try container.decode(String.self)
        guard hex.count == 64, let data = Data(hexadecimal: hex) else {
            throw EFBError.malformedEncoding(field: "SHA256Digest")
        }
        try self.init(bytes: data)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(hexString)
    }
}

extension Data {
    public init?(hexadecimal hex: String) {
        guard hex.count % 2 == 0 else { return nil }
        var data = Data(capacity: hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            data.append(byte)
            index = next
        }
        self = data
    }
}
