// CrewCredentialStore.swift
// 凭据在本机的存放与取用。所有条目都用 secureStore 保存。

import Foundation
import EFBCore
import EFBCryptography

public final class CrewCredentialStore: @unchecked Sendable {
    private let store: SecureStoring
    private static let servicePrefix = "efb.crew."
    private static let indexItem = SecureStoreItem(service: "efb.crew.index", account: "crews")

    public init(store: SecureStoring) {
        self.store = store
    }

    private func item(for crew: CrewID) -> SecureStoreItem {
        SecureStoreItem(service: Self.servicePrefix + crew.rawValue, account: "credential")
    }

    public func save(_ record: CrewCredentialRecord) throws {
        try store.writeCodable(record, to: item(for: record.crewID))
        var index = (try? enrolledCrew()) ?? []
        if !index.contains(record.crewID) {
            index.append(record.crewID)
            try store.writeCodable(index.sorted(), to: Self.indexItem)
        }
    }

    public func load(_ crew: CrewID) throws -> CrewCredentialRecord? {
        try store.readCodable(CrewCredentialRecord.self, from: item(for: crew))
    }

    public func delete(_ crew: CrewID) throws {
        try store.delete(item(for: crew))
        var index = (try? enrolledCrew()) ?? []
        index.removeAll { $0 == crew }
        try store.writeCodable(index.sorted(), to: Self.indexItem)
    }

    /// 读取某机组的历史 PIN 校验器（需要先解开密封件）。
    public func historyVerifiers(for crew: CrewID) throws -> [PINVerifier] {
        guard let record = try load(crew) else { return [] }
        let sealingKey = SecureEnclaveSealingKey(blob: record.sealingKeyBlob)
        let plaintext = try sealingKey.open(record.sealedPayload)
        return try JSONDecoder().decode(SealedCredentialPayload.self, from: plaintext).pinHistory
    }

    /// 本机已预置的全部机组成员。
    public func enrolledCrew() throws -> [CrewID] {
        let index = try store.readCodable([CrewID].self, from: Self.indexItem) ?? []
        return index
    }
}
