import Foundation

/// Hasil satu kali menjalankan puttygen.
struct RunResult {
    let status: Int32
    let crashed: Bool
    let out: String
    let err: String
    var ok: Bool { status == 0 && !crashed }

    /// Pesan error yang mudah dibaca, tanpa awalan "puttygen: ".
    var message: String {
        let text = (err.isEmpty ? out : err)
            .components(separatedBy: "\n")
            .map { $0.hasPrefix("puttygen: ") ? String($0.dropFirst(10)) : $0 }
            .filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
            .joined(separator: "\n")
        if crashed { return text.isEmpty ? "puttygen berhenti mendadak (crash)." : "puttygen berhenti mendadak (crash).\n" + text }
        return text.isEmpty ? "puttygen gagal (kode \(status))." : text
    }

    var needsPassphrase: Bool {
        let e = err.lowercased()
        return e.contains("wrong passphrase") || e.contains("decryption check failed")
    }
}

struct AppError: Error {
    let message: String
    var code: String = "error"
}

/// Informasi kunci yang sedang dibuka, dikirim ke tampilan.
struct KeyInfo {
    var pubBody: String      // public key tanpa komentar
    var comment: String
    var fingerprint: String
    var algorithm: String
    var bits: String
    var isSSH1: Bool
    var hasCert: Bool

    var dict: [String: Any] {
        ["pubBody": pubBody, "comment": comment, "fingerprint": fingerprint,
         "algorithm": algorithm, "bits": bits, "isSSH1": isSSH1, "hasCert": hasCert]
    }
}

/// Membungkus binary puttygen. Kunci yang sedang dikerjakan disimpan di folder
/// sementara privat (0700), selalu terenkripsi dengan passphrase sesi acak yang
/// hanya ada di memori.
final class Puttygen {
    let exe: URL
    let workDir: URL
    private let session: String
    private var workKey: URL? = nil
    private(set) var isSSH1 = false

    static func locate() -> URL? {
        var candidates: [String] = []
        if let bundled = Bundle.main.url(forResource: "puttygen", withExtension: nil) {
            candidates.append(bundled.path)
        }
        candidates += ["/opt/homebrew/bin/puttygen", "/usr/local/bin/puttygen", "/usr/bin/puttygen"]
        return candidates.first { FileManager.default.isExecutableFile(atPath: $0) }.map(URL.init(fileURLWithPath:))
    }

    init?() {
        guard let exe = Puttygen.locate() else { return nil }
        self.exe = exe
        workDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("PuTTYgenMac-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        session = bytes.map { String(format: "%02x", $0) }.joined()
    }

    func cleanup() {
        try? FileManager.default.removeItem(at: workDir)
    }

    var hasKey: Bool { workKey != nil }

    // MARK: - Proses

    func run(_ args: [String]) async -> RunResult {
        let exe = self.exe
        return await withCheckedContinuation { cont in
            DispatchQueue.global(qos: .userInitiated).async {
                let p = Process()
                p.executableURL = exe
                p.arguments = args
                p.standardInput = FileHandle.nullDevice
                let out = Pipe(), err = Pipe()
                p.standardOutput = out
                p.standardError = err
                do { try p.run() } catch {
                    cont.resume(returning: RunResult(status: -1, crashed: false, out: "",
                                                     err: error.localizedDescription))
                    return
                }
                var errData = Data()
                let group = DispatchGroup()
                group.enter()
                DispatchQueue.global().async {
                    errData = err.fileHandleForReading.readDataToEndOfFile()
                    group.leave()
                }
                let outData = out.fileHandleForReading.readDataToEndOfFile()
                group.wait()
                p.waitUntilExit()
                cont.resume(returning: RunResult(
                    status: p.terminationStatus,
                    crashed: p.terminationReason == .uncaughtSignal,
                    out: String(decoding: outData, as: UTF8.self),
                    err: String(decoding: errData, as: UTF8.self)))
            }
        }
    }

    func version() async -> String {
        let r = await run(["--version"])
        let line = r.out.components(separatedBy: "\n").first { $0.contains("Release") } ?? ""
        return line.replacingOccurrences(of: "puttygen: ", with: "")
    }

    /// Menulis passphrase ke file 0600 sementara, lalu menghapusnya setelah dipakai.
    private func secretFile(_ text: String) throws -> URL {
        let url = workDir.appendingPathComponent("p-\(UUID().uuidString)")
        guard FileManager.default.createFile(atPath: url.path, contents: Data(text.utf8),
                                             attributes: [.posixPermissions: 0o600]) else {
            throw AppError(message: "Tidak bisa menulis file sementara.")
        }
        return url
    }

    private func newWorkURL() -> URL {
        workDir.appendingPathComponent("key-\(UUID().uuidString)")
    }

    private func adopt(_ url: URL, ssh1: Bool) {
        if let old = workKey { try? FileManager.default.removeItem(at: old) }
        workKey = url
        isSSH1 = ssh1
    }

    private func requireKey() throws -> URL {
        guard let k = workKey else { throw AppError(message: "Belum ada kunci.") }
        return k
    }

    // MARK: - Membuat & memuat

    struct GenOptions {
        var type: String        // rsa, dsa, ecdsa, eddsa, rsa1
        var bits: Int
        var curve: String       // nistp256/384/521, ed25519/ed448
        var primes: String      // probable, proven, proven-even
        var strong: Bool
    }

    func generate(_ o: GenOptions) async throws -> KeyInfo {
        let sess = try secretFile(session)
        defer { try? FileManager.default.removeItem(at: sess) }
        let dest = newWorkURL()
        var args: [String] = ["-q"]
        switch o.type {
        case "eddsa":
            args += ["-t", o.curve == "ed448" ? "ed448" : "ed25519"]
        case "ecdsa":
            let b = ["nistp256": 256, "nistp384": 384, "nistp521": 521][o.curve] ?? 256
            args += ["-t", "ecdsa", "-b", String(b)]
        default:
            args += ["-t", o.type, "-b", String(o.bits)]
            args += ["--primes", o.primes]
            if o.strong && o.type != "dsa" { args.append("--strong-rsa") }
        }
        args += ["--new-passphrase", sess.path, "-o", dest.path]
        let r = await run(args)
        guard r.ok else {
            try? FileManager.default.removeItem(at: dest)
            var msg = r.message
            if r.crashed && o.primes != "probable" {
                msg += "\n\nOpsi \"proven primes\" diketahui membuat puttygen versi ini crash. Pakai \"probable primes\" saja."
            }
            throw AppError(message: msg)
        }
        adopt(dest, ssh1: o.type == "rsa1")
        return try await info(fingerprintType: "sha256")
    }

    /// Mendeskripsikan format file kunci berdasarkan isinya.
    static func describeFormat(_ url: URL) -> (native: Bool, ssh1: Bool, name: String) {
        let head = (try? FileHandle(forReadingFrom: url).readData(ofLength: 200)) ?? Data()
        let s = String(decoding: head, as: UTF8.self)
        if s.hasPrefix("PuTTY-User-Key-File-") { return (true, false, "PuTTY private key") }
        if s.hasPrefix("SSH PRIVATE KEY FILE FORMAT 1.1") { return (true, true, "SSH-1 private key") }
        if s.contains("BEGIN OPENSSH PRIVATE KEY") { return (false, false, "OpenSSH SSH-2 private key (format baru)") }
        if s.contains("BEGIN RSA PRIVATE KEY") || s.contains("BEGIN DSA PRIVATE KEY") || s.contains("BEGIN EC PRIVATE KEY") {
            return (false, false, "OpenSSH SSH-2 private key (format PEM lama)")
        }
        if s.contains("BEGIN SSH2 ENCRYPTED PRIVATE KEY") { return (false, false, "ssh.com SSH-2 private key") }
        return (false, false, "format tidak dikenal")
    }

    func load(path: String, passphrase: String) async throws -> (KeyInfo, (native: Bool, ssh1: Bool, name: String)) {
        let src = URL(fileURLWithPath: path)
        let fmt = Puttygen.describeFormat(src)
        let old = try secretFile(passphrase)
        let sess = try secretFile(session)
        defer {
            try? FileManager.default.removeItem(at: old)
            try? FileManager.default.removeItem(at: sess)
        }
        let dest = newWorkURL()
        let r = await run([path, "--old-passphrase", old.path, "--new-passphrase", sess.path,
                           "--reencrypt", "-O", "private", "-o", dest.path])
        guard r.ok else {
            try? FileManager.default.removeItem(at: dest)
            if r.needsPassphrase {
                throw AppError(message: passphrase.isEmpty ? "Kunci ini dilindungi passphrase." : "Passphrase salah.",
                               code: "needPassphrase")
            }
            throw AppError(message: "Tidak bisa memuat kunci.\n" + r.message)
        }
        adopt(dest, ssh1: Puttygen.describeFormat(dest).ssh1)
        return (try await info(fingerprintType: "sha256"), fmt)
    }

    // MARK: - Informasi

    func info(fingerprintType: String) async throws -> KeyInfo {
        let key = try requireKey()
        let pub = await run([key.path, "-L"])
        guard pub.ok else { throw AppError(message: pub.message) }
        let line = pub.out.trimmingCharacters(in: .newlines)
        let fp = try await fingerprint(type: fingerprintType)

        var body = line, comment = ""
        // SSH-2: "tipe base64 komentar"; SSH-1: "bits e n komentar"
        let nFields = isSSH1 ? 3 : 2
        var parts = line.split(separator: " ", maxSplits: nFields, omittingEmptySubsequences: false).map(String.init)
        if parts.count > nFields {
            comment = parts.removeLast()
        }
        body = parts.joined(separator: " ")

        let fpParts = fp.split(separator: " ").map(String.init)
        let algorithm = isSSH1 ? "SSH-1 RSA" : (fpParts.first ?? "")
        let bits = isSSH1 ? (fpParts.first ?? "") : (fpParts.count > 1 ? fpParts[1] : "")
        return KeyInfo(pubBody: body, comment: comment, fingerprint: fp, algorithm: algorithm,
                       bits: bits, isSSH1: isSSH1, hasCert: algorithm.contains("-cert-v01@openssh.com"))
    }

    func fingerprint(type: String) async throws -> String {
        let key = try requireKey()
        var args = [key.path, "-l"]
        if !isSSH1 { args += ["-E", type] }
        let r = await run(args)
        guard r.ok else { throw AppError(message: r.message) }
        var fp = r.out.trimmingCharacters(in: .newlines)
        if isSSH1 {
            // "1024 aa:bb:... komentar" -> buang komentar, sama seperti SSH-2
            let p = fp.split(separator: " ", maxSplits: 2).map(String.init)
            fp = p.prefix(2).joined(separator: " ")
        }
        return fp
    }

    func certInfo() async throws -> String {
        let key = try requireKey()
        let r = await run([key.path, "-O", "cert-info"])
        guard r.ok else { throw AppError(message: r.message) }
        return r.out
    }

    // MARK: - Menyimpan & ekspor

    /// outType: private, private-openssh, private-openssh-new, private-sshcom
    func exportPrivate(to dest: URL, outType: String, comment: String, passphrase: String, ppkParam: String?) async throws {
        let key = try requireKey()
        let sess = try secretFile(session)
        let newp = try secretFile(passphrase)
        defer {
            try? FileManager.default.removeItem(at: sess)
            try? FileManager.default.removeItem(at: newp)
        }
        let tmp = newWorkURL()
        var args = [key.path, "--old-passphrase", sess.path, "--new-passphrase", newp.path,
                    "-C", comment, "--reencrypt", "-O", outType, "-o", tmp.path]
        if outType == "private", !isSSH1, let p = ppkParam, !p.isEmpty {
            args += ["--ppk-param", p]
        }
        let r = await run(args)
        guard r.ok else {
            try? FileManager.default.removeItem(at: tmp)
            throw AppError(message: "Gagal menyimpan kunci.\n" + r.message)
        }
        try replace(dest, with: tmp)
    }

    func savePublic(to dest: URL, comment: String) async throws {
        let key = try requireKey()
        let sess = try secretFile(session)
        defer { try? FileManager.default.removeItem(at: sess) }
        // puttygen tidak bisa langsung "-C komentar -p", jadi terapkan komentar ke salinan dulu.
        let withComment = newWorkURL()
        defer { try? FileManager.default.removeItem(at: withComment) }
        let r1 = await run([key.path, "--old-passphrase", sess.path, "--new-passphrase", sess.path,
                            "-C", comment, "--reencrypt", "-O", "private", "-o", withComment.path])
        guard r1.ok else { throw AppError(message: r1.message) }
        let tmp = newWorkURL()
        let r2 = await run([withComment.path, "-O", "public", "-o", tmp.path])
        guard r2.ok else {
            try? FileManager.default.removeItem(at: tmp)
            throw AppError(message: "Gagal menyimpan public key.\n" + r2.message)
        }
        try replace(dest, with: tmp)
    }

    private func replace(_ dest: URL, with tmp: URL) throws {
        let fm = FileManager.default
        if fm.fileExists(atPath: dest.path) {
            _ = try fm.replaceItemAt(dest, withItemAt: tmp)
        } else {
            try fm.moveItem(at: tmp, to: dest)
        }
    }

    // MARK: - Sertifikat

    func setCertificate(_ certPath: String?) async throws -> KeyInfo {
        let key = try requireKey()
        let sess = try secretFile(session)
        defer { try? FileManager.default.removeItem(at: sess) }
        let dest = newWorkURL()
        var args = [key.path, "--old-passphrase", sess.path, "--new-passphrase", sess.path]
        if let c = certPath { args += ["--certificate", c] } else { args.append("--remove-certificate") }
        args += ["-O", "private", "-o", dest.path]
        let r = await run(args)
        guard r.ok else {
            try? FileManager.default.removeItem(at: dest)
            throw AppError(message: r.message)
        }
        adopt(dest, ssh1: isSSH1)
        return try await info(fingerprintType: "sha256")
    }
}
