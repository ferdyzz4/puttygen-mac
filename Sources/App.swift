import Cocoa
import WebKit
import UniformTypeIdentifiers

@main
final class AppDelegate: NSObject, NSApplicationDelegate, WKScriptMessageHandlerWithReply,
                         WKNavigationDelegate, NSMenuItemValidation, NSWindowDelegate {
    var window: NSWindow!
    var web: WKWebView!
    var pg: Puttygen?
    var pageReady = false
    var pendingOpen: [String] = []
    /// Keadaan tampilan, dikirim dari JS lewat "syncMenu" (untuk centang & enable menu).
    var ui: [String: Any] = [:]

    static func main() {
        let app = NSApplication.shared
        let delegate = AppDelegate()
        app.delegate = delegate
        app.setActivationPolicy(.regular)
        app.run()
    }

    // MARK: - Siklus aplikasi

    func applicationDidFinishLaunching(_ notification: Notification) {
        pg = Puttygen()
        buildMenu()

        let config = WKWebViewConfiguration()
        config.userContentController.addScriptMessageHandler(self, contentWorld: .page, name: "api")
        web = WKWebView(frame: .zero, configuration: config)
        web.navigationDelegate = self
        web.setValue(false, forKey: "drawsBackground")
        web.allowsMagnification = false

        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 980, height: 840),
                          styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
                          backing: .buffered, defer: false)
        window.title = "PuTTYgen"
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        window.minSize = NSSize(width: 640, height: 600)
        window.contentView = web
        window.delegate = self
        window.setFrameAutosaveName("MainWindow")
        if !window.setFrameUsingName("MainWindow") { window.center() }
        window.makeKeyAndOrderFront(nil)

        if let dir = Bundle.main.url(forResource: "web", withExtension: nil) {
            web.loadFileURL(dir.appendingPathComponent("index.html"), allowingReadAccessTo: dir)
        }
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }

    func applicationWillTerminate(_ notification: Notification) {
        pg?.cleanup()
    }

    func application(_ application: NSApplication, open urls: [URL]) {
        for url in urls where url.isFileURL {
            openInPage(url.path)
        }
    }

    func openInPage(_ path: String) {
        guard pageReady else { pendingOpen.append(path); return }
        callJS("app.openFile", path)
    }

    func callJS(_ fn: String, _ arg: String) {
        let data = (try? JSONSerialization.data(withJSONObject: [arg])) ?? Data("[\"\"]".utf8)
        let json = String(decoding: data, as: UTF8.self)
        web.evaluateJavaScript("\(fn)(...\(json))", completionHandler: nil)
    }

    // MARK: - Navigasi (file yang di-drop ke jendela)

    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let url = action.request.url else { return decisionHandler(.cancel) }
        if url.isFileURL, url.lastPathComponent == "index.html",
           url.path.hasPrefix(Bundle.main.bundlePath) {
            return decisionHandler(.allow)
        }
        if url.isFileURL {
            openInPage(url.path)
        } else if url.scheme == "https" || url.scheme == "http" {
            NSWorkspace.shared.open(url)
        }
        decisionHandler(.cancel)
    }

    // MARK: - Jembatan JS -> Swift

    func userContentController(_ userContentController: WKUserContentController,
                               didReceive message: WKScriptMessage,
                               replyHandler: @escaping (Any?, String?) -> Void) {
        guard let body = message.body as? [String: Any], let cmd = body["cmd"] as? String else {
            return replyHandler(["ok": false, "error": "Perintah tidak valid."], nil)
        }
        let args = body["args"] as? [String: Any] ?? [:]
        Task { @MainActor in
            do {
                var result = try await self.handle(cmd, args)
                result["ok"] = true
                replyHandler(result, nil)
            } catch let e as AppError {
                replyHandler(["ok": false, "error": e.message, "code": e.code], nil)
            } catch {
                replyHandler(["ok": false, "error": error.localizedDescription, "code": "error"], nil)
            }
        }
    }

    @MainActor
    func handle(_ cmd: String, _ a: [String: Any]) async throws -> [String: Any] {
        if cmd == "init" {
            pageReady = true
            let files = pendingOpen
            pendingOpen = []
            DispatchQueue.main.async { files.forEach(self.openInPage) }
            guard let pg else {
                return ["available": false]
            }
            return ["available": true, "version": await pg.version(), "path": pg.exe.path]
        }
        if cmd == "syncMenu" {
            ui = a
            return [:]
        }
        if cmd == "openURL", let s = a["url"] as? String, let url = URL(string: s) {
            NSWorkspace.shared.open(url)
            return [:]
        }
        guard let pg else { throw AppError(message: "puttygen tidak ditemukan.") }
        let str = { (k: String) in a[k] as? String ?? "" }

        switch cmd {
        case "generate":
            let o = Puttygen.GenOptions(type: str("type"), bits: (a["bits"] as? Int) ?? 2048,
                                        curve: str("curve"), primes: str("primes").isEmpty ? "probable" : str("primes"),
                                        strong: a["strong"] as? Bool ?? false)
            let info = try await pg.generate(o)
            return ["key": info.dict]

        case "pickKeyFile":
            let panel = NSOpenPanel()
            panel.title = str("title").isEmpty ? "Muat private key" : str("title")
            panel.allowsMultipleSelection = false
            panel.canChooseDirectories = false
            panel.showsHiddenFiles = true
            let ssh = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh")
            if FileManager.default.fileExists(atPath: ssh.path) { panel.directoryURL = ssh }
            guard await present(panel) == .OK, let url = panel.url else { return ["cancelled": true] }
            return ["path": url.path]

        case "load":
            let path = str("path")
            let (info, fmt) = try await pg.load(path: path, passphrase: str("passphrase"))
            return ["key": info.dict, "native": fmt.native, "format": fmt.name,
                    "name": (path as NSString).lastPathComponent]

        case "fingerprint":
            return ["fingerprint": try await pg.fingerprint(type: str("type"))]

        case "savePublic":
            guard let url = await askSave(title: "Simpan public key", name: str("suggest") + ".pub") else {
                return ["cancelled": true]
            }
            try await pg.savePublic(to: url, comment: str("comment"))
            return ["path": url.path]

        case "savePrivate":
            let outType = str("outType")
            let ext = outType == "private" ? (pg.isSSH1 ? "" : ".ppk") : ""
            let titles = ["private": "Simpan private key",
                          "private-openssh": "Export OpenSSH key",
                          "private-openssh-new": "Export OpenSSH key (format baru)",
                          "private-sshcom": "Export ssh.com key"]
            guard let url = await askSave(title: titles[outType] ?? "Simpan", name: str("suggest") + ext) else {
                return ["cancelled": true]
            }
            try await pg.exportPrivate(to: url, outType: outType, comment: str("comment"),
                                       passphrase: str("passphrase"), ppkParam: a["ppkParam"] as? String)
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
            return ["path": url.path]

        case "addCert":
            let panel = NSOpenPanel()
            panel.title = "Pilih file sertifikat"
            panel.allowsMultipleSelection = false
            guard await present(panel) == .OK, let url = panel.url else { return ["cancelled": true] }
            return ["key": try await pg.setCertificate(url.path).dict]

        case "removeCert":
            return ["key": try await pg.setCertificate(nil).dict]

        case "certInfo":
            return ["text": try await pg.certInfo()]

        case "reveal":
            NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: str("path"))])
            return [:]

        default:
            throw AppError(message: "Perintah tidak dikenal: \(cmd)")
        }
    }

    @MainActor
    func present(_ panel: NSSavePanel) async -> NSApplication.ModalResponse {
        await withCheckedContinuation { cont in
            panel.beginSheetModal(for: window) { cont.resume(returning: $0) }
        }
    }

    @MainActor
    func askSave(title: String, name: String) async -> URL? {
        let panel = NSSavePanel()
        panel.title = title
        panel.nameFieldStringValue = name
        panel.canCreateDirectories = true
        panel.showsHiddenFiles = true
        panel.isExtensionHidden = false
        guard await present(panel) == .OK else { return nil }
        return panel.url
    }

    // MARK: - Menu (meniru menu PuTTYgen di Windows)

    func item(_ title: String, _ action: String, key: String = "", mods: NSEvent.ModifierFlags = [.command]) -> NSMenuItem {
        let m = NSMenuItem(title: title, action: #selector(menuAction(_:)), keyEquivalent: key)
        m.keyEquivalentModifierMask = mods
        m.representedObject = action
        m.target = self
        return m
    }

    func buildMenu() {
        let main = NSMenu()

        let appMenu = NSMenu()
        appMenu.addItem(item("Tentang PuTTYgen", "about", key: ""))
        appMenu.addItem(.separator())
        let services = NSMenuItem(title: "Services", action: nil, keyEquivalent: "")
        services.submenu = NSMenu()
        NSApp.servicesMenu = services.submenu
        appMenu.addItem(services)
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Sembunyikan PuTTYgen", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        let hideOthers = appMenu.addItem(withTitle: "Sembunyikan Lainnya", action: #selector(NSApplication.hideOtherApplications(_:)), keyEquivalent: "h")
        hideOthers.keyEquivalentModifierMask = [.command, .option]
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Keluar dari PuTTYgen", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        add(appMenu, "PuTTYgen", to: main)

        let file = NSMenu(title: "File")
        file.addItem(item("Muat private key…", "load", key: "o"))
        file.addItem(item("Simpan public key…", "savePublic", key: "s", mods: [.command, .shift]))
        file.addItem(item("Simpan private key…", "savePrivate", key: "s"))
        file.addItem(.separator())
        file.addItem(withTitle: "Tutup Jendela", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        add(file, "File", to: main)

        let edit = NSMenu(title: "Edit")
        edit.addItem(withTitle: "Undo", action: Selector(("undo:")), keyEquivalent: "z")
        let redo = edit.addItem(withTitle: "Redo", action: Selector(("redo:")), keyEquivalent: "z")
        redo.keyEquivalentModifierMask = [.command, .shift]
        edit.addItem(.separator())
        edit.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        edit.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        edit.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        edit.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        add(edit, "Edit", to: main)

        let key = NSMenu(title: "Key")
        key.addItem(item("Generate pasangan kunci", "generate", key: "g"))
        key.addItem(.separator())
        key.addItem(item("SSH-1 key (RSA)", "type:rsa1", key: ""))
        key.addItem(item("SSH-2 RSA key", "type:rsa", key: ""))
        key.addItem(item("SSH-2 DSA key", "type:dsa", key: ""))
        key.addItem(item("SSH-2 ECDSA key", "type:ecdsa", key: ""))
        key.addItem(item("SSH-2 EdDSA key", "type:eddsa", key: ""))
        key.addItem(.separator())
        key.addItem(item("Pakai probable primes (cepat)", "primes:probable", key: ""))
        key.addItem(item("Pakai proven primes (lebih lambat)", "primes:proven", key: ""))
        key.addItem(item("Pakai proven primes dengan distribusi merata (paling lambat)", "primes:proven-even", key: ""))
        key.addItem(.separator())
        key.addItem(item("Pakai \"strong\" primes sebagai faktor kunci RSA", "strong", key: ""))
        key.addItem(.separator())
        key.addItem(item("Parameter untuk menyimpan file kunci…", "params", key: ","))
        key.addItem(.separator())
        key.addItem(item("Tampilkan fingerprint sebagai SHA256", "fp:sha256", key: ""))
        key.addItem(item("Tampilkan fingerprint sebagai MD5", "fp:md5", key: ""))
        key.addItem(item("Tampilkan fingerprint SHA256 termasuk sertifikat", "fp:sha256-cert", key: ""))
        key.addItem(item("Tampilkan fingerprint MD5 termasuk sertifikat", "fp:md5-cert", key: ""))
        key.addItem(.separator())
        key.addItem(item("Tambahkan sertifikat ke kunci…", "addCert", key: ""))
        key.addItem(item("Hapus sertifikat dari kunci", "removeCert", key: ""))
        key.addItem(item("Info sertifikat…", "certInfo", key: ""))
        add(key, "Key", to: main)

        let conv = NSMenu(title: "Conversions")
        conv.addItem(item("Import key…", "import", key: "i"))
        conv.addItem(item("Export OpenSSH key…", "exportOpenSSH", key: "e"))
        conv.addItem(item("Export OpenSSH key (paksa format baru)…", "exportOpenSSHNew", key: "e", mods: [.command, .shift]))
        conv.addItem(item("Export ssh.com key…", "exportSshcom", key: ""))
        add(conv, "Conversions", to: main)

        let win = NSMenu(title: "Window")
        win.addItem(withTitle: "Minimize", action: #selector(NSWindow.performMiniaturize(_:)), keyEquivalent: "m")
        win.addItem(withTitle: "Zoom", action: #selector(NSWindow.performZoom(_:)), keyEquivalent: "")
        add(win, "Window", to: main)
        NSApp.windowsMenu = win

        let help = NSMenu(title: "Help")
        help.addItem(item("Tentang PuTTYgen", "about", key: ""))
        add(help, "Help", to: main)
        NSApp.helpMenu = help

        NSApp.mainMenu = main
    }

    private func add(_ menu: NSMenu, _ title: String, to main: NSMenu) {
        let top = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        menu.title = title
        top.submenu = menu
        main.addItem(top)
    }

    @objc func menuAction(_ sender: NSMenuItem) {
        guard let action = sender.representedObject as? String else { return }
        callJS("app.onMenu", action)
    }

    func validateMenuItem(_ menuItem: NSMenuItem) -> Bool {
        guard let action = menuItem.representedObject as? String else { return true }
        let busy = ui["busy"] as? Bool ?? false
        let hasKey = ui["hasKey"] as? Bool ?? false
        let ssh1 = ui["isSSH1"] as? Bool ?? false
        let algo = ui["algorithm"] as? String ?? ""
        let hasCert = ui["hasCert"] as? Bool ?? false
        let type = ui["type"] as? String ?? ""

        let parts = action.split(separator: ":", maxSplits: 1).map(String.init)
        if parts.count == 2 {
            let current: String
            switch parts[0] {
            case "type": current = type
            case "primes": current = ui["primes"] as? String ?? "probable"
            case "fp": current = ui["fp"] as? String ?? "sha256"
            default: current = ""
            }
            menuItem.state = current == parts[1] ? .on : .off
            if parts[0] == "primes" { return !busy && ["rsa", "dsa", "rsa1"].contains(type) }
            if parts[0] == "fp" { return !ssh1 }
            return !busy
        }
        switch action {
        case "strong":
            menuItem.state = (ui["strong"] as? Bool ?? false) ? .on : .off
            return !busy && (type == "rsa" || type == "rsa1")
        case "about", "params": return true
        case "generate", "load", "import": return !busy
        case "savePublic", "savePrivate": return !busy && hasKey
        case "exportOpenSSH", "exportOpenSSHNew": return !busy && hasKey && !ssh1
        case "exportSshcom": return !busy && hasKey && (algo == "ssh-rsa" || algo == "ssh-dss")
        case "addCert": return !busy && hasKey && !ssh1
        case "removeCert", "certInfo": return !busy && hasKey && hasCert
        default: return true
        }
    }
}
