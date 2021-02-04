import 'dart:typed_data';

import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/asymmetric/api.dart';

import 'common.dart';
import 'crl.dart';
import 'pkcs7.dart';
import 'pkcs7_signer_info.dart';
import 'ts.dart';
import 'x509.dart';

/// A Pkcs7 Message Builder
class Pkcs7Builder with Pkcs {
  /// Creates a Pkcs7 message builder
  Pkcs7Builder();

  final _digestAlgorithms = <ASN1Sequence>[];

  final _contentInfo = ASN1Sequence(elements: [
    ASN1ObjectIdentifier([1, 2, 840, 113549, 1, 7, 1])
  ]);

  final _certificates = <X509>[];

  final _crl = <CertificateRevocationList>[];

  final _signerInfos = <Pkcs7SignerInfoBuilder>{};

  /// Add an X509 certificate to the Pkcs7 message
  void addCertificate(X509 certificate) {
    _certificates.add(certificate);
  }

  /// Add a certificate revocation list to the Pkcs7 message
  void addCRL(CertificateRevocationList crl) {
    _crl.add(crl);
  }

  /// Add a signature
  void addSignerInfo(Pkcs7SignerInfoBuilder signerInfo) {
    _signerInfos.add(signerInfo);
    _digestAlgorithms.add(ASN1Sequence(elements: [
      signerInfo.digestAlgorithmID,
    ]));
  }

  /// Generate the Pkcs7 message
  Pkcs7 build() {
    final asn1 = ASN1Sequence();
    asn1.add(ASN1ObjectIdentifier([1, 2, 840, 113549, 1, 7, 2]));

    final data = ASN1Sequence();
    data.add(ASN1Integer.fromtInt(1)); // Version
    data.add(ASN1Set(elements: _digestAlgorithms.toList())); // digestAlgorithms
    data.add(_contentInfo); // contentInfo

    if (_certificates.isNotEmpty) {
      final certData =
          _certificates.map((x) => x.asn1.encode()).expand((x) => x).toList();
      final cert = ASN1OctetString(
        octets: Uint8List.fromList(certData),
        tag: 0xa0,
      );
      data.add(cert); // Certificates
    }

    if (_crl.isNotEmpty) {
      final crlData =
          _crl.map((x) => x.asn1.encode()).expand((x) => x).toList();
      final cert = ASN1OctetString(
        octets: Uint8List.fromList(crlData),
        tag: 0xa1,
      );
      data.add(cert); // Certificates
    }

    final signerInfo = ASN1Set(
      elements: _signerInfos.map((i) => i.build().asn1).toList(),
    );
    data.add(signerInfo); // Signer Info

    asn1.add(ASN1OctetString(octets: data.encode(), tag: 0xa0));
    asn1.encode();

    return Pkcs7(asn1);
  }
}

/// A Pkcs7 Signer Info Builder
abstract class Pkcs7SignerInfoBuilder with Pkcs {
  /// Creates a Pkcs7 Signer Info Builder
  Pkcs7SignerInfoBuilder(this.issuer);

  /// Build an RSA Pkcs7 Signer
  factory Pkcs7SignerInfoBuilder.rsa({
    required X509 issuer,
    HashAlgorithm digestAlgorithm = HashAlgorithm.sha1,
    required RSAPrivateKey privateKey,
  }) {
    return _RSAPkcs7SignerInfoBuilder(
      issuer,
      privateKey,
      digestAlgorithm,
    );
  }

  /// Signing X509 Certificate
  final X509 issuer;

  /// Digest algorithm to use
  ASN1ObjectIdentifier get digestAlgorithmID;

  /// Entryption algorithm to use
  ASN1ObjectIdentifier get digestEncryptionAlgorithmID;

  final _authenticatedAttributes = <ASN1Sequence>[];

  final _unauthenticatedAttributes = <ASN1Sequence>[];

  Uint8List? _signature;

  /// Add the Secure/Multipurpose Internet Mail Extensions digest
  void addSMimeDigest({required Uint8List digest, DateTime? signingTime}) {
    _authenticatedAttributes.add(ASN1Sequence(elements: [
      ASN1ObjectIdentifier([1, 2, 840, 113549, 1, 9, 3]), // ContentType
      ASN1Set(elements: [
        ASN1ObjectIdentifier([1, 2, 840, 113549, 1, 7, 1]), // Data
      ])
    ]));

    signingTime ??= DateTime.now();
    _authenticatedAttributes.add(ASN1Sequence(elements: [
      ASN1ObjectIdentifier([1, 2, 840, 113549, 1, 9, 5]), // SigningTime
      ASN1Set(elements: [
        ASN1UtcTime(signingTime.toUtc()),
      ])
    ]));

    _authenticatedAttributes.add(ASN1Sequence(elements: [
      ASN1ObjectIdentifier([1, 2, 840, 113549, 1, 9, 4]), // MessageDigest
      ASN1Set(elements: [
        ASN1OctetString(octets: digest),
      ])
    ]));
  }

  /// Generate a Timestamp Query message
  Uint8List generateTSQ();

  /// Add a timestamp to the digest
  void addTimestamp({required TimestampResponse tsr}) {
    _unauthenticatedAttributes.add(ASN1Sequence(elements: [
      ASN1ObjectIdentifier(
          [1, 2, 840, 113549, 1, 9, 16, 2, 14]), // id-aa-timeStampToken
      ASN1Set(elements: [tsr.timeStampToken])
    ]));
  }

  /// Message to be signed
  Uint8List get message => ASN1Set(elements: _authenticatedAttributes).encode();

  /// Build the Pkcs7SignerInfo
  Pkcs7SignerInfo build() {
    final asn1 = ASN1Sequence();
    asn1.add(ASN1Integer.fromtInt(1)); // Version
    asn1.add(issuer.asn1Issuer); // Issuer and Serial

    // Digest Algorithm
    asn1.add(ASN1Sequence(elements: [
      digestAlgorithmID,
      ASN1Null(),
    ]));

    // Authenticated Attributes
    if (_authenticatedAttributes.isNotEmpty) {
      final certData = _authenticatedAttributes
          .map((x) => x.encode())
          .expand((x) => x)
          .toList();
      final cert = ASN1OctetString(
        octets: Uint8List.fromList(certData),
        tag: 0xa0,
      );
      asn1.add(cert);
    }

    // Digest Encryption Algorithm
    asn1.add(ASN1Sequence(elements: [
      digestEncryptionAlgorithmID,
      ASN1Null(),
    ]));

    // Encrypted Digest
    asn1.add(ASN1OctetString(
      octets: signature,
    ));

    // Unauthenticated Attributes
    if (_unauthenticatedAttributes.isNotEmpty) {
      final certData = _unauthenticatedAttributes
          .map((x) => x.encode())
          .expand((x) => x)
          .toList();
      final cert = ASN1OctetString(
        octets: Uint8List.fromList(certData),
        tag: 0xa1,
      );
      asn1.add(cert);
    }

    return Pkcs7SignerInfo(asn1);
  }

  /// The message signature
  Uint8List get signature {
    _signature ??= sign(message);
    return _signature!;
  }

  /// Sign the message
  Uint8List sign(Uint8List message);
}

/// A Pkcs7 Signer Info Builder
class _RSAPkcs7SignerInfoBuilder extends Pkcs7SignerInfoBuilder {
  _RSAPkcs7SignerInfoBuilder(
    X509 issuer,
    this.privateKey,
    this.digestAlgorithm,
  ) : super(issuer);

  final RSAPrivateKey privateKey;

  final HashAlgorithm digestAlgorithm;

  @override
  ASN1ObjectIdentifier get digestAlgorithmID =>
      ASN1ObjectIdentifier(Pkcs.hashAlgorithmIdentifiers[digestAlgorithm]);

  @override
  ASN1ObjectIdentifier get digestEncryptionAlgorithmID =>
      ASN1ObjectIdentifier.fromName('rsaEncryption');

  @override
  Uint8List generateTSQ() {
    final tsDigest = getDigest(digestAlgorithm);
    final tsHash = tsDigest.process(signature);
    return TimestampResponse.generateRequest(digestAlgorithm, tsHash);
  }

  @override
  Uint8List sign(Uint8List message) {
    return issuer.generateSignature(
      privateKey,
      message,
      digestAlgorithm,
    );
  }
}
