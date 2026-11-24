// main.swift
// 校验器入口。

import Foundation

let h = Harness()
runCoreSuites(h)
runCryptoSuites(h)
await runIdentityAndReleaseSuites(h)
runSessionSuites(h)
await runTamperSuites(h)
await runAttackSuites(h)
await runArchiveSuites(h)
await runCockpitAppSuites(h)
exit(h.summary())
