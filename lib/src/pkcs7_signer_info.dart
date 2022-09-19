import 'dart:typed_data';

import 'package:pointycastle/asn1.dart';

import 'common.dart';

/// Pkcs7 message signature
class Pkcs7SignerInfo with Pkcs {
  /// parse a Pkcs7 message signature
  factory Pkcs7SignerInfo(ASN1Sequence asn1) {
    ASN1Object? signedAttrs;
    ASN1Sequence? signatureAlgorithm;
    ASN1OctetString? signature;
    ASN1Object? unsignedAttrs;

    for (final e in asn1.elements!.sublist(3)) {
      if (e.tag == 0xa0) {
        signedAttrs = e;
      } else if (e.tag == 0xa1) {
        unsignedAttrs = e;
      } else if (e is ASN1Sequence) {
        signatureAlgorithm = e;
      } else if (e is ASN1OctetString) {
        signature = e;
      }
    }

    return Pkcs7SignerInfo._(
      asn1,
      signedAttrs,
      signatureAlgorithm!,
      signature!,
      unsignedAttrs,
    );
  }

  const Pkcs7SignerInfo._(
    this._asn1,
    this._signedAttrs,
    this._signatureAlgorithm,
    this._signature,
    this._unsignedAttrs,
  );

  final ASN1Sequence _asn1;

  final ASN1Object? _signedAttrs;

  final ASN1Sequence _signatureAlgorithm;

  final ASN1OctetString _signature;

  final ASN1Object? _unsignedAttrs;

  /// The SignerInfo asn1 object
  ASN1Sequence get asn1 => _asn1;

  /// The version number of the signature.
  int get version {
    final ver = _asn1.elements![0] as ASN1Integer;
    return ver.integer!.toInt();
  }

  /// The issuer of the certificate.
  Iterable<MapEntry<ASN1ObjectIdentifier, dynamic>> get issuer {
    final issuer = _asn1.elements![1] as ASN1Sequence;
    return namesFromAsn1(issuer.elements![0] as ASN1Sequence);
  }

  /// The version number of the signature.
  int get serial {
    final issuer = _asn1.elements![1] as ASN1Sequence;
    final ser = issuer.elements![1] as ASN1Integer;
    return ser.integer!.toInt();
  }

  /// The digest Algorithm ID.
  ASN1ObjectIdentifier get digestAlgorithmID {
    final digest = _asn1.elements![2] as ASN1Sequence;
    return digest.elements![0] as ASN1ObjectIdentifier;
  }

  /// The digest Algorithm
  HashAlgorithm get digestAlgorithm {
    return commonDigestAlgorithm(digestAlgorithmID);
  }

  /// Signed attributes
  Iterable<MapEntry<ASN1ObjectIdentifier, List<ASN1Object>>>
      get signedAttributes sync* {
    if (_signedAttrs == null) {
      return;
    }

    var o = 0;
    while (o < _signedAttrs!.valueByteLength!) {
      final c = ASN1Parser(_signedAttrs!.valueBytes!.sublist(o)).nextObject()
          as ASN1Sequence;

      final id = c.elements![0] as ASN1ObjectIdentifier;
      final value = c.elements![1] as ASN1Set;
      yield MapEntry<ASN1ObjectIdentifier, List<ASN1Object>>(
          id, value.elements!);

      o += c.encodedBytes!.lengthInBytes;
    }
  }

  /// Non-signed attributes
  Iterable<MapEntry<ASN1ObjectIdentifier, List<ASN1Object>>>
      get unsignedAttributes sync* {
    if (_unsignedAttrs == null) {
      return;
    }

    var o = 0;
    while (o < _unsignedAttrs!.valueByteLength!) {
      final c = ASN1Parser(_unsignedAttrs!.valueBytes!.sublist(o)).nextObject()
          as ASN1Sequence;

      final id = c.elements![0] as ASN1ObjectIdentifier;
      final value = c.elements![1] as ASN1Set;
      yield MapEntry<ASN1ObjectIdentifier, List<ASN1Object>>(
          id, value.elements!);

      o += c.encodedBytes!.lengthInBytes;
    }
  }

  /// The signature Algorithm ID.
  ASN1ObjectIdentifier get signatureAlgorithmID {
    return _signatureAlgorithm.elements![0] as ASN1ObjectIdentifier;
  }

  /// The digest Algorithm
  Uint8List get signature {
    return _signature.octets!;
  }

  /// The embedded message content type, if any
  ASN1ObjectIdentifier? get contentType {
    for (final attr in signedAttributes) {
      if (attr.key.objectIdentifierAsString == Pkcs.contentType) {
        return attr.value[0] as ASN1ObjectIdentifier;
      }
    }
    return null;
  }

  /// The embedded message digest, if any
  Uint8List? get messageDigest {
    for (final attr in signedAttributes) {
      if (attr.key.objectIdentifierAsString == Pkcs.messageDigest) {
        final digest = attr.value[0] as ASN1OctetString;
        return digest.octets;
      }
    }
    return null;
  }

  /// The embedded message signature time, if any
  DateTime? get signingTime {
    for (final attr in signedAttributes) {
      if (attr.key.objectIdentifierAsString == Pkcs.signingTime) {
        final digest = attr.value[0] as ASN1UtcTime;
        return digest.time!;
      }
    }
    return null;
  }

  @override
  String toString() {
    final b = StringBuffer();
    b.writeln('$runtimeType');
    b.writeln('  Version: $version');
    b.writeln('  Issuer');
    for (final entry in issuer) {
      b.writeln('    ${entry.key.name}: ${asn1ToString(entry.value)}');
    }
    b.writeln('  Serial: $serial');
    b.writeln('  Digest Algorithm: ${digestAlgorithmID.name}');
    b.writeln('  Signed Attributes:');
    for (final entry in signedAttributes) {
      b.writeln(
          '    ${entry.key.name}: ${entry.value.map((e) => asn1ToString(e)).join(', ')}');
    }
    b.writeln('  Signature Algorithm: ${signatureAlgorithmID.name}');
    b.writeln('  Signature: ${toHex(signature)}');
    b.writeln('  Non-signed Attributes:');
    for (final entry in unsignedAttributes) {
      b.writeln(
          '    ${entry.key.name}: ${entry.value.map((e) => asn1ToString(e)).join(', ')}');
    }
    return b.toString();
  }
}
