//
//  SettingView.swift
//  Asspp
//
//  Created by 秋星桥 on 2024/7/11.
//

import ApplePackage
import SwiftUI

#if canImport(UIKit)
    import UIKit
#endif

struct SettingView: View {
    @Environment(\.openURL) private var openURL
    @State private var vm = AppStore.this

    @State private var deviceIdTapCount = 0
    @State private var showDeviceIdWarning = false
    @State private var editingDeviceId = false
    @State private var deviceIdDraft = ""
    @State private var showResetConfirmation = false

    var body: some View {
        NavigationStack {
            formContent
        }
    }

    private func saveDeviceID() {
        let trimmed = deviceIdDraft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        // The AppStore setter also propagates this to ApplePackage.Configuration.
        vm.deviceIdentifier = trimmed
        editingDeviceId = false
    }

    private var formContent: some View {
        Form {
            Section {
                Toggle("Demo Mode", isOn: $vm.demoMode)
                Button("Delete All Downloads", role: .destructive) {
                    Downloads.this.removeAll()
                }
            } header: {
                Text("General")
            } footer: {
                Text("Demo mode redacts all accounts and sensitive information.")
            }

            Section {
                Text(ProcessInfo.processInfo.hostName)
                    .redacted(reason: .placeholder, isEnabled: vm.demoMode)
                if editingDeviceId {
                    TextField("Device GUID", text: $deviceIdDraft)
                        .font(.system(.body, design: .monospaced))
                        .autocorrectionDisabled()
                    #if canImport(UIKit)
                        .textInputAutocapitalization(.never)
                    #endif
                    #if os(macOS)
                        HStack {
                            Button("Save") { saveDeviceID() }
                            Button("Cancel", role: .destructive) {
                                editingDeviceId = false
                            }
                            Spacer()
                        }
                    #else
                        Button("Save") { saveDeviceID() }
                        Button("Cancel", role: .destructive) {
                            editingDeviceId = false
                        }
                    #endif
                } else {
                    Text(vm.deviceIdentifier)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                        .redacted(reason: .placeholder, isEnabled: vm.demoMode)
                    #if os(macOS)
                        HStack {
                            Button("Open Settings") {
                                openURL(URL(string: "x-apple.systempreferences:")!)
                            }
                            Button("Show Certificate in Finder") {
                                NSWorkspace.shared.activateFileViewerSelecting([Installer.ca])
                            }
                            Spacer()
                        }
                    #else
                        Button("Open Settings") {
                            openURL(URL(string: UIApplication.openSettingsURLString)!)
                        }
                        Button("Install Certificate") {
                            openURL(Installer.caURL)
                        }
                    #endif
                }
            } header: {
                Text("Device")
                    .onTapGesture {
                        deviceIdTapCount += 1
                        if deviceIdTapCount >= 10 {
                            deviceIdTapCount = 0
                            showDeviceIdWarning = true
                        }
                    }
            } footer: {
                #if canImport(UIKit)
                    Text("Grant local network permission to install apps. Install and trust the SSL certificate for on-device installation.")
                #else
                    Text("Grant local network permission to install apps. Install the SSL certificate through System Keychain.")
                #endif
            }
            .alert("Edit Device GUID", isPresented: $showDeviceIdWarning) {
                Button("Edit", role: .destructive) {
                    deviceIdDraft = vm.deviceIdentifier
                    editingDeviceId = true
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("Changing the device GUID may cause all existing accounts to stop working. Apple limits the number of devices you can sign in with at once.")
            }

            Section {
                Link("@Lakr233", destination: URL(string: "https://twitter.com/Lakr233")!)
                Link("Buy me a coffee! ☕️", destination: URL(string: "https://github.com/sponsors/Lakr233/")!)
            } header: {
                Text("About")
            } footer: {
                Text("Hope this app helps you!")
            }

            Section {
                Button("Reset", role: .destructive) {
                    showResetConfirmation = true
                }
            } header: {
                Text("Danger Zone")
            } footer: {
                Text("This will reset all your settings.")
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Settings")
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                NavigationLink {
                    LogView()
                } label: {
                    Image(systemName: "doc.text.magnifyingglass")
                }
            }
        }
        .alert("Reset Application", isPresented: $showResetConfirmation) {
            Button("Reset", role: .destructive) {
                try? FileManager.default.removeItem(at: documentsDirectory)
                try? FileManager.default.removeItem(at: temporaryDirectory)
                #if canImport(UIKit)
                    UIApplication.shared.perform(#selector(NSXPCConnection.suspend))
                #endif
                #if canImport(AppKit) && !canImport(UIKit)
                    NSApp.terminate(nil)
                #endif
                Task { @MainActor in
                    try? await Task.sleep(for: .seconds(1))
                    exit(0)
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This will reset all your settings and data. The app will close afterwards.")
        }
    }
}
