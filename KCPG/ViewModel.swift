//
//  ViewModel.swift
//  KCPG
//
//  Created by Stefan Walkner on 17.05.21.
//

import Foundation
import LocalAuthentication
import OSLog

class ViewModel {

    enum Variant {
        case writeIdentityWithBiometrics
        case writePrivateKeyWithBiometrics
    }

    private let variant: Variant = .writePrivateKeyWithBiometrics

    init() {
        DispatchQueue.main.async { self.tryout() }
    }

    func getBioSecAccessControl() -> SecAccessControl {
        let access = SecAccessControlCreateWithFlags(nil, // Use the default allocator.
                                                     kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                     .userPresence,
                                                     nil) // Ignore any error.
        precondition(access != nil, "SecAccessControlCreateWithFlags failed")
        return access!
    }

    func tryout() {
        deleteAllKeysInKeyChain()
        deleteCertificates()
        deleteIdentities()

        let privKeyAttrApplicationLabel = "com.example.keys.privateKey.kSecAttrApplicationLabel".data(using: .utf8)!

        let privKeyAttrApplicationTag = "com.example.keys.privateKey.kSecAttrApplicationTag".data(using: .utf8)!

        let pubKeyAttrApplicationTag = "com.example.keys.publicKey.kSecAttrApplicationTag".data(using: .utf8)!

        let privateKeyAttributes: [String: Any]

        if variant == .writePrivateKeyWithBiometrics {
            privateKeyAttributes = [kSecAttrIsPermanent as String:    true,
                                    kSecAttrAccessControl as String: getBioSecAccessControl(),
                                    kSecAttrApplicationLabel as String: privKeyAttrApplicationLabel,
                                    kSecAttrApplicationTag as String: privKeyAttrApplicationTag]
        } else {
            privateKeyAttributes = [kSecAttrIsPermanent as String:    true,
                                    kSecAttrApplicationLabel as String: privKeyAttrApplicationLabel,
                                    kSecAttrApplicationTag as String: privKeyAttrApplicationTag]
        }

        let keyPairAttributes: [String: Any] =
            [kSecAttrKeyType as String:            kSecAttrKeyTypeRSA,
             kSecAttrKeySizeInBits as String:      2048,
             kSecPrivateKeyAttrs as String: privateKeyAttributes,
             kSecPublicKeyAttrs as String:
                [kSecAttrIsPermanent: true,
                 kSecAttrApplicationTag: pubKeyAttrApplicationTag]
            ]

        var publicKeyRef: SecKey? = nil

        var privateKeyRef: SecKey? = nil

        let keyPairGenerationStatus = SecKeyGeneratePair(keyPairAttributes as CFDictionary, &publicKeyRef, &privateKeyRef)

        debugPrint(keyPairGenerationStatus)
        guard keyPairGenerationStatus == errSecSuccess else { return }

        // At this stage I create CSR using above pair of keys and do exchane it to PEM (X509) to finaly parse that to DER

        let pemCert: String =
            """
            MIICVjCCAb8CAg37MA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG
            A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE
            MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl
            YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw
            ODIyMDUyNzIzWhcNMTcwODIxMDUyNzIzWjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE
            CAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs
            ZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMYBBrx5PlP0WNI/ZdzD
            +6Pktmurn+F2kQYbtc7XQh8/LTBvCo+P6iZoLEmUA9e7EXLRxgU1CVqeAi7QcAn9
            MwBlc8ksFJHB0rtf9pmf8Oza9E0Bynlq/4/Kb1x+d+AyhL7oK9tQwB24uHOueHi1
            C/iVv8CSWKiYe6hzN1txYe8rAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAASPdjigJ
            kXCqKWpnZ/Oc75EUcMi6HztaW8abUMlYXPIgkV2F7YanHOB7K4f7OOLjiz8DTPFf
            jC9UeuErhaA/zzWi8ewMTFZW/WshOrm3fNvcMrMLKtH534JKvcdMg6qIdjTFINIr
            evnAhf0cwULaebn+lMs8Pdl7y37+sfluVok=
        """

        let pemCertData = NSData(base64Encoded: pemCert, options:NSData.Base64DecodingOptions.ignoreUnknownCharacters)!

        // Before adding the certificate to the keychain, delete the public key from the keychain.  There are situations where the presence of the public key confuses the identity matching code.

        let deletePublicKeyQuery: [String: Any] = [kSecClass as String: kSecClassKey,

                                                   kSecAttrKeyType as String: kSecAttrKeyTypeRSA,

                                                   kSecAttrApplicationTag as String: pubKeyAttrApplicationTag,

                                                   kSecReturnRef as String: true]

        let deletePublicKeyStatus = SecItemDelete(deletePublicKeyQuery as CFDictionary)

        debugPrint(deletePublicKeyStatus)
        guard deletePublicKeyStatus == errSecSuccess else { return }

        guard let cert = SecCertificateCreateWithData(kCFAllocatorDefault, pemCertData as CFData) else { return }
        debugPrint("after cert")

        // Add cer to keychain

        let addquery: [String: Any] = [kSecClass as String: kSecClassCertificate,
                                       kSecValueRef as String: cert,
                                       kSecAttrPublicKeyHash as String: privKeyAttrApplicationLabel,
                                       kSecAttrLabel as String: "com.example.keys.mycert"]

        let certAddStatus = SecItemAdd(addquery as CFDictionary, nil)

        debugPrint(certAddStatus)
        guard certAddStatus == errSecSuccess else { return }

        if variant == .writePrivateKeyWithBiometrics {
            debugPrint("before getIdentityQuery")
            let getIdentityQuery: [String: Any] = [kSecClass as String: kSecClassIdentity,
                                                   kSecReturnRef as String: true,
                                                   kSecAttrApplicationTag as String: privKeyAttrApplicationTag]

            var identityItem: CFTypeRef?

            debugPrint("before SecItemCopyMatching", getIdentityQuery)
            let status = SecItemCopyMatching(getIdentityQuery as CFDictionary, &identityItem)
            debugPrint("after SecItemCopyMatching", getIdentityQuery)
            debugPrint(status)
            debugPrint(status, identityItem)
        } else {
            let getIdentityQuery: [String: Any] = [kSecClass as String: kSecClassIdentity,
                                                   kSecReturnRef as String: true,
                                                   kSecAttrApplicationTag as String: privKeyAttrApplicationTag]

            var secIdentity: CFTypeRef?

            let status = SecItemCopyMatching(getIdentityQuery as CFDictionary, &secIdentity)
            debugPrint("8735", status, secIdentity)




            // Notice that kSecClass as String: kSecClassIdentity is not being used here as this is inferred from kSecValueRef.
            let identityAddition: [String: Any] = [
                kSecValueRef as String: secIdentity,
                kSecAttrLabel as String: "ListenerIdentity"
            ]

            let indetityStatus = SecItemAdd(identityAddition as CFDictionary, nil)

            guard indetityStatus == errSecSuccess else {
                os_log("Error: couldn???t add identity: %{public}@", indetityStatus)
                return
            }
            os_log("Added identity SUCCESSFULLY %d", indetityStatus)

            // On the query, kSecClassIdentity is used to make sure a SecIdentity is extracted.
            let identityQuery: [String: Any] = [
                kSecClass as String: kSecClassIdentity,
                kSecReturnRef as String: true,
                kSecAttrLabel as String: "ListenerIdentity"
            ]
            var identityItem: CFTypeRef?
            let getIdentityStatus = SecItemCopyMatching(identityQuery as CFDictionary, &identityItem)

            guard getIdentityStatus == errSecSuccess else {
                os_log("Error: couldn???t get identity: %d", getIdentityStatus)
                return
            }
            let secIdentityNew = identityItem as! SecIdentity
            debugPrint(secIdentityNew)







//
//
//
//
//
//
//
//
//
//
//
//            let identityAddition: [String: Any] = [
//                kSecValueRef as String: secIdentity,
//                kSecAttrLabel as String: "ListenerIdentity"
//            ]
//
//            let identityStatus = SecItemAdd(identityAddition as CFDictionary, nil)
//            debugPrint("8735", identityStatus)
//
//            let getIdentityQueryBio: [String: Any] =  [
//                kSecClass as String: kSecClassIdentity,
//                kSecReturnRef as String: true,
//                kSecAttrLabel as String: "ListenerIdentity"
//            ]
//
//            var identityItemBio: CFTypeRef?
//
//            let statusBio = SecItemCopyMatching(getIdentityQueryBio as CFDictionary, &identityItemBio)
//            debugPrint("8735", statusBio, identityItemBio)
        }
    }

    func deleteAllKeysInKeyChain() {

        let query: [String: Any] = [String(kSecClass): kSecClassKey]

        let status = SecItemDelete(query as CFDictionary)

        switch status {
        case errSecItemNotFound:
            print("No key in keychain")
        case noErr:
            print("All Keys Deleted!")
        default:
            print("SecItemDelete error! \(status.description)")
        }
    }

    func deleteCertificates() {

        let query: [String: Any] = [String(kSecClass): kSecClassCertificate]

        let status = SecItemDelete(query as CFDictionary)

        switch status {
        case errSecItemNotFound:
            print("No cert in keychain")
        case noErr:
            print("All certs Deleted!")
        default:
            print("SecItemDelete error! \(status.description)")
        }

    }

    func deleteIdentities() {

        let query: [String: Any] = [String(kSecClass): kSecClassIdentity]

        let status = SecItemDelete(query as CFDictionary)

        switch status {
        case errSecItemNotFound:
            print("No identity in keychain")
        case noErr:
            print("All identities Deleted!")
        default:
            print("SecItemDelete error! \(status.description)")
        }

    }
}
