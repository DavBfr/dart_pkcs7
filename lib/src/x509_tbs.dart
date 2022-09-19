import 'dart:typed_data';

import 'package:pem/pem.dart';
import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/asymmetric/api.dart';

import 'common.dart';

/// An X.509 Certificate
class X509Tbs with Pkcs {
  /// Creates a certificate from an [ASN1Sequence].
  X509Tbs(this._tbs) : _offset = _tbs.elements![1] is ASN1Integer ? 0 : -1;

  /// Creates a X.509 Certificate from DER encoded bytes.
  factory X509Tbs.fromDer(Uint8List der) => X509Tbs(
        ASN1Parser(der).nextObject() as ASN1Sequence,
      );

  /// Creates a certificate from a PEM encoded string.
  factory X509Tbs.fromPem(String pem) => X509Tbs.fromDer(
        Uint8List.fromList(
          PemCodec(PemLabel.certificate).decode(pem),
        ),
      );

  final ASN1Sequence _tbs;

  final int _offset;

  Uint8List? _fingerprint;

  /// The Public Key Algorithm of the certificate.
  ASN1ObjectIdentifier get publicKeyAlgorithmOI {
    final key = _tbs.elements![_offset + 6] as ASN1Sequence;
    final sig = key.elements![0] as ASN1Sequence;
    return sig.elements![0] as ASN1ObjectIdentifier;
  }

  /// The Public Key Algorithm of the certificate.
  Uint8List get publicKeyBytes {
    final key = _tbs.elements![_offset + 6] as ASN1Sequence;
    final str = key.elements![1] as ASN1BitString;
    return Uint8List.fromList(str.stringValues!);
  }

  /// The Public Key Algorithm of the certificate.
  RSAPublicKey get publicKey {
    switch (publicKeyAlgorithmOI.objectIdentifierAsString) {
      case Pkcs.RsaesPkcs1:
        final s = ASN1Parser(publicKeyBytes).nextObject() as ASN1Sequence;
        final asn1Modulus = s.elements![0] as ASN1Integer;
        final modulus = asn1Modulus.integer!;
        final asn1Exponent = s.elements![1] as ASN1Integer;
        final exponent = asn1Exponent.integer!;
        return RSAPublicKey(modulus, exponent);
    }
    throw UnimplementedError('Unknown algorithm ${publicKeyAlgorithmOI.name}');
  }

  /// The version number of the certificate.
  int get version {
    if (_offset != 0) {
      return 1;
    }
    final e =
        ASN1Parser(_tbs.elements!.first.valueBytes).nextObject() as ASN1Integer;
    return e.integer!.toInt() + 1;
  }

  /// The serial number of the certificate.
  BigInt get serialNumber {
    final sn = _tbs.elements![_offset + 1] as ASN1Integer;
    return sn.integer!;
  }

  /// The digest Algorithm ID of the certificate.
  ASN1ObjectIdentifier get digestAlgorithmID {
    final sig = _tbs.elements![_offset + 2] as ASN1Sequence;
    return sig.elements![0] as ASN1ObjectIdentifier;
  }

  /// The parameters for the signature algorithm ID of the certificate.
  ASN1Object get signatureAlgorithmIDParameters {
    final sig = _tbs.elements![_offset + 2] as ASN1Sequence;
    return sig.elements![1];
  }

  /// The issuer of the certificate.
  Iterable<MapEntry<ASN1ObjectIdentifier, dynamic>> get issuer {
    return namesFromAsn1(_tbs.elements![_offset + 3] as ASN1Sequence);
  }

  /// The issuer of the certificate represented as asn1.
  ASN1Sequence get asn1Issuer {
    final issuer = ASN1Object.fromBytes(
      ASN1Parser(_tbs.elements![_offset + 3].encode()).nextObject().encode(),
    );
    final serial = ASN1Object.fromBytes(
      ASN1Parser(_tbs.elements![_offset + 1].encode()).nextObject().encode(),
    );

    return ASN1Sequence(elements: [issuer, serial]);
  }

  /// The start time which this certificate is valid.
  DateTime get notBefore {
    final validity = _tbs.elements![_offset + 4] as ASN1Sequence;
    final time = validity.elements![0];
    if (time is ASN1UtcTime) {
      return time.time!;
    }
    if (time is ASN1GeneralizedTime) {
      return time.dateTimeValue!.toUtc();
    }
    throw Exception('Unable to decode time');
  }

  /// The end time which this certificate is valid.
  DateTime get notAfter {
    final validity = _tbs.elements![_offset + 4] as ASN1Sequence;
    final time = validity.elements![1];
    if (time is ASN1UtcTime) {
      return time.time!;
    }
    if (time is ASN1GeneralizedTime) {
      return time.dateTimeValue!.toUtc();
    }
    throw Exception('Unable to decode time');
  }

  /// The subject of the certificate.
  Iterable<MapEntry<ASN1ObjectIdentifier, dynamic>> get subject {
    return namesFromAsn1(_tbs.elements![_offset + 5] as ASN1Sequence);
  }

  /// The digest Algorithm
  HashAlgorithm get digestAlgorithm {
    return commonDigestAlgorithm(digestAlgorithmID);
  }

  /// The X509 TBS certificate asn1 object
  ASN1Sequence get asn1 => _tbs;

  /// The sngned body of the certificate
  Uint8List get body => _tbs.encodedBytes!;

  /// The certificate fingerprint
  Uint8List get fingerprint {
    if (_fingerprint == null) {
      final algo = getDigest(digestAlgorithm);
      _fingerprint = algo.process(body);
    }
    return _fingerprint!;
  }

  @override
  bool operator ==(Object other) {
    if (other is X509Tbs) {
      return listEquality(fingerprint, other.fingerprint);
    }

    return false;
  }

  @override
  int get hashCode => fingerprint.reduce((a, b) => a + b);

  @override
  String toString() {
    final b = StringBuffer();
    b.writeln('$runtimeType');
    b.writeln('  Version: $version');
    b.writeln('  Serial: $serialNumber');
    b.writeln('  Signature Algorithm ID: ${digestAlgorithmID.name}');
    b.writeln('  Fingerprint: ${toHex(fingerprint)}');
    b.writeln('  Not Before: $notBefore');
    b.writeln('  Not After: $notAfter');
    b.writeln('  Subject:');
    for (final entry in subject) {
      b.writeln('    ${entry.key.name}: ${asn1ToString(entry.value)}');
    }
    b.writeln('  Issuer');
    for (final entry in issuer) {
      b.writeln('    ${entry.key.name}: ${asn1ToString(entry.value)}');
    }
    b.writeln('  Public Key:');
    b.writeln('    Algorithm: ${publicKeyAlgorithmOI.name}');
    b.writeln('    Key: ${toHex(publicKeyBytes)}');
    return b.toString();
  }
}
