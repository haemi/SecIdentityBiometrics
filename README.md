# SecIdentityBiometrics
What I try to achieve is generating a RSA 2048bit key pair, where the public key is sent to the server. The server sends a x.509 certificate back.

With my private key and the certificate, I need to create a `SecIdentity` (used for URLAuthChallenge). This works when I do not use biometrics to protect the private key.

But as soon as I add biometrics, I'm unable to fetch the `SecIdentity`. I tried with two variants:

```
    enum Variant {
        case writeIdentityWithBiometrics
        case writePrivateKeyWithBiometrics
    }
```

## writeIdentityWithBiometrics
Here I add `kSecAttrAccessControl` to the private key directly and try to read the `SecIdentity` in the end.

## writePrivateKeyWithBiometrics
Here I first add the keypair, then the certificate to the keychain - everything without biometrics. Then I read the `SecIdentity` and try to add it with `kSecAttrAccessControl`.