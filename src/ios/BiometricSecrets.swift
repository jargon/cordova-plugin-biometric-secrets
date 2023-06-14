import LocalAuthentication

@objc(BiometricSecrets) class BiometricSecrets : CDVPlugin {
    struct Credentials {
        var username: String
        var password: String
        var server: String
    }

    struct KeychainError: Error {
        var status: OSStatus

        var localizedDescription: String {
            return SecCopyErrorMessageString(status, nil) as String? ?? "Unknown error"
        }
    }

    @objc(addCredentials:)
    func addCredentials(command: CDVInvokedUrlCommand) {

    }

    func addCredentialsCore(_ credentials: Credentials) throws {
        let account = credentials.username
        let password = credentials.password.data(using: String.Encoding.utf8)!

        let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .userPresence, nil)

        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 10

        let query: [String: Any] = [
            kSecClass as String: kSecClassInternetPassword,
            kSecAttrAccount as String: account,
            kSecAttrServer as String: server,
            kSecAttrAccessControl as String: access as Any,
            kSecUseAuthenticationContext as String: context,
            kSecValueData as String: password
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError(status: status)
        }
    }

    func readCredentialsCore(server: String, prompt: String) throws -> Credentials {
        let query: [String: Any] = [
            kSecClass as String: kSecClassInternetPassword,
            kSecAttrServer as String: server,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnAttributes as String: true,
            kSecUseOperationPrompt as String: prompt,
            kSecReturnData as String: true
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            throw KeychainError(status: status)
        }

        guard let existingItem = item as? [String: Any],
            let passwordData = existingItem[kSecValueData as String] as? Data,
            let password = String(data: passwordData, encoding: String.Encoding.utf8),
            let account = existingItem[kSecAttrAccount as String] as? String
            else {
                throw KeychainError(status: errSecInternalError)
        }

        return Credentials(username: account, password: password)
    }

    func readCredentialsCore(username: String, server: String, prompt: String) throws -> Credentials {
        let query: [String: Any] = [
            kSecClass as String: kSecClassInternetPassword,
            kSecAttrAccount as String: username,
            kSecAttrServer as String: server,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnAttributes as String: true,
            kSecUseOperationPrompt as String: prompt,
            kSecReturnData as String: true
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            throw KeychainError(status: status)
        }

        guard let existingItem = item as? [String: Any],
            let passwordData = existingItem[kSecValueData as String] as? Data,
            let password = String(data: passwordData, encoding: String.Encoding.utf8)
            else {
                throw KeychainError(status: errSecInternalError)
        }

        return Credentials(username: username, password: password)
    }

    func removeCredentialsCore(server: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassInternetPassword,
            kSecAttrServer as String: server
        ]

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess else {
            throw KeychainError(status: status)
        }
    }

    func removeCredentialsCore(username: String, server: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassInternetPassword,
            kSecAttrAccount as String: username,
            kSecAttrServer as String: server
        ]

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess else {
            throw KeychainError(status: status)
        }
    }
}
