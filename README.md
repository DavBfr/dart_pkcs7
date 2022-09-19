# Pkcs7

Pkcs7 message parser and verification library.

Can parse and generate x509 certificates, request Timestamp,
build and verify an s-mime PKCS #7 message.

## X509 Certificates

```dart
final cert = X509.fromPem(CA);
print(cert);
print(cert.pem);
```

## Pkcs7 message

```dart
final pkcs7Builder = Pkcs7Builder();
// Add one or more certificates
pkcs7Builder.addCertificate(cert);

// Create a signature information object
final signerInfo = Pkcs7SignerInfoBuilder.rsa(issuer: issuer, privateKey: privateKey);

// Add the digest to sign
signerInfo.addSMimeDigest(digest: hash);

// Generate a timestamp request and submit to a remote server
final tsq = signerInfo.generateTSQ();
final tsr = await myTimestampSign!(tsq);
if (tsr != null) {
  signerInfo.addTimestamp(tsr: TimestampResponse.fromDer(tsr));
}

// Add the signature information
pkcs7Builder.addSignerInfo(signerInfo);

// Add a certificate revocation list
pkcs7Builder.addCRL(CertificateRevocationList.fromPem(crl));

final pkcs7 = pkcs7Builder.build();
print(pkcs7);
print(pkcs7.pem);
```

## Verify a signature

```dart
final si = pkcs7.verify([CA]);
final algo = si.getDigest(si.digestAlgorithm);
si.listEquality(hash, si.messageDigest);
```
