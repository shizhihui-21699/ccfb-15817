// ReleaseArchive.swift
// 离线放行记录的本地归档与上传队列。
//
// 驾驶舱里没有网络，签字完成后记录必须先在本地安全保存，落地后由地面系统拉取。
// 这里给出：
//   * 用 SecureStoring 持久化（Keychain / 加密文件均可），保证卸载前不丢；
//   * 上传队列（按时间排序），地面系统按序消费；
//   * 消费后标记，避免重复上传导致公司侧令牌被误判为 "已消耗两次"。

import Foundation
import EFBCore
import EFBCryptography

public final class ReleaseArchive: @unchecked Sendable {
    private let store: SecureStoring
    private let mutex = NSLock()
    private static let service = "efb.archive"

    public init(store: SecureStoring) {
        self.store = store
    }

    private func item(_ recordID: String) -> SecureStoreItem {
        SecureStoreItem(service: Self.service, account: recordID)
    }

    private static let indexItem = SecureStoreItem(service: "efb.archive.index", account: "records")
    private static let uploadedItem = SecureStoreItem(service: "efb.archive.index", account: "uploaded")

    /// 保存一条已封存的记录。幂等：同 recordID 覆盖。
    public func archive(_ record: ReleaseRecord) throws {
        try store.writeCodable(record, to: item(record.recordID))
        mutex.lock()
        defer { mutex.unlock() }
        var index = try store.readCodable([String].self, from: Self.indexItem) ?? []
        if !index.contains(record.recordID) {
            index.append(record.recordID)
            try store.writeCodable(index, to: Self.indexItem)
        }
    }

    public func record(_ recordID: String) throws -> ReleaseRecord? {
        try store.readCodable(ReleaseRecord.self, from: item(recordID))
    }

    public func allRecordIDs() throws -> [String] {
        try store.readCodable([String].self, from: Self.indexItem) ?? []
    }

    /// 待上传队列（按 recordID 字典序，实际部署可按签名时间排序）。
    public func pendingUpload() throws -> [ReleaseRecord] {
        let ids = try allRecordIDs().filter { !(try uploadedIDs()).contains($0) }
        return try ids.compactMap { try record($0) }
    }

    public func markUploaded(_ recordID: String) throws {
        mutex.lock()
        defer { mutex.unlock() }
        var uploaded = (try? store.readCodable([String].self, from: Self.uploadedItem)) ?? []
        if !uploaded.contains(recordID) {
            uploaded.append(recordID)
            try store.writeCodable(uploaded, to: Self.uploadedItem)
        }
    }

    private func uploadedIDs() throws -> Set<String> {
        Set(try store.readCodable([String].self, from: Self.uploadedItem) ?? [])
    }
}
