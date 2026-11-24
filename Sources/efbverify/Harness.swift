// Harness.swift
// 极简校验框架。
//
// 本机只有 Command Line Tools，既没有 XCTest 也没有 swift-testing（实测均无该模块），
// 因此校验改为一个可执行程序：逐条执行断言，打印结果，有任一失败则退出码非零，
// 可直接接入 CI。

import Foundation

public final class Harness: @unchecked Sendable {
    private var failures = 0
    private var checks = 0

    public init() {}

    public func suite(_ name: String, _ body: () throws -> Void) {
        print("\n▸ \(name)")
        do {
            try body()
        } catch {
            failures += 1
            print("  ✗ 套件抛出未预期错误：\(error)")
        }
    }

    public func asyncSuite(_ name: String, _ body: () async throws -> Void) async {
        print("\n▸ \(name)")
        do {
            try await body()
        } catch {
            failures += 1
            print("  ✗ 套件抛出未预期错误：\(error)")
        }
    }

    public func expect(_ condition: Bool, _ message: String, line: UInt = #line) {
        checks += 1
        if condition {
            print("  ✓ \(message)")
        } else {
            failures += 1
            print("  ✗ \(message)  [line \(line)]")
        }
    }

    public func expectEqual<T: Equatable>(_ actual: T, _ expected: T, _ message: String, line: UInt = #line) {
        expect(actual == expected, "\(message)（实际 \(actual)，期望 \(expected)）", line: line)
    }

    /// 期望闭包抛出指定错误。
    public func expectThrows<E: Error & Equatable>(
        _ expected: E, _ message: String, line: UInt = #line,
        _ body: () throws -> Void
    ) {
        do {
            try body()
            expect(false, "\(message)（未抛出错误）", line: line)
        } catch let error as E {
            expect(error == expected, "\(message)（抛出 \(error)）", line: line)
        } catch {
            expect(false, "\(message)（抛出了其它错误 \(error)）", line: line)
        }
    }

    /// 期望闭包抛出任意错误，且错误等于预期（不关心具体类型）。
    public func expectThrowsAny(_ message: String, line: UInt = #line, _ body: () throws -> Void) {
        do {
            try body()
            expect(false, "\(message)（未抛出错误）", line: line)
        } catch {
            expect(true, "\(message)（抛出 \(error)）", line: line)
        }
    }

    /// 期望异步闭包抛出任意错误。
    public func expectThrowsAnyAsync(_ message: String, line: UInt = #line, _ body: () async throws -> Void) async {
        do {
            try await body()
            expect(false, "\(message)（未抛出错误）", line: line)
        } catch {
            expect(true, "\(message)（抛出 \(error)）", line: line)
        }
    }

    /// 期望异步闭包不抛出。
    public func expectNoThrowAsync(_ message: String, line: UInt = #line, _ body: () async throws -> Void) async {
        do {
            try await body()
            expect(true, message, line: line)
        } catch {
            expect(false, "\(message)（意外抛出 \(error)）", line: line)
        }
    }

    /// 期望闭包不抛出。
    public func expectNoThrow(_ message: String, line: UInt = #line, _ body: () throws -> Void) {
        do {
            try body()
            expect(true, message, line: line)
        } catch {
            expect(false, "\(message)（意外抛出 \(error)）", line: line)
        }
    }

    public func summary() -> Int32 {
        print("\n" + String(repeating: "─", count: 66))
        if failures == 0 {
            print("全部通过：\(checks) 项断言")
            return 0
        }
        print("失败：\(failures) / \(checks)")
        return 1
    }
}
