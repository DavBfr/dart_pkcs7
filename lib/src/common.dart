// ignore_for_file: public_member_api_docs

import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/export.dart';

/// Dignature digest to use for document authenticity verification
enum HashAlgorithm {
  /// Use sha1 hash
  sha1,

  /// Use sha256 hash
  sha256,

  /// Use sha385 hash
  sha384,

  /// Use sha512 hash
  sha512,
}

mixin Pkcs {
  static const contentType = '1.2.840.113549.1.9.3';
  static const data = '1.2.840.113549.1.7.1';
  static const ecdsaWithSha256 = '1.2.840.10045.4.3.2';
  static const ecdsaWithSha384 = '1.2.840.10045.4.3.3';
  static const ecdsaWithSha512 = '1.2.840.10045.4.3.4';
  static const emailAddress = '1.2.840.113549.1.9.1';
  static const messageDigest = '1.2.840.113549.1.9.4';
  static const netscapeComment = '2.16.840.1.113730.1.13';
  static const organizationIdentifier = '2.5.4.97';
  static const rsaEncryption = '1.2.840.113549.1.1.1';
  static const sha1 = '1.3.14.3.2.26';
  static const sha1WithRsaSignature = '1.2.840.113549.1.1.5';
  static const sha256 = '2.16.840.1.101.3.4.2.1';
  static const sha256WithRSAEncryption = '1.2.840.113549.1.1.11';
  static const sha384 = '2.16.840.1.101.3.4.2.2';
  static const sha384WithRSAEncryption = '1.2.840.113549.1.1.12';
  static const sha512 = '2.16.840.1.101.3.4.2.3';
  static const sha512WithRSAEncryption = '1.2.840.113549.1.1.13';
  static const signedData = '1.2.840.113549.1.7.2';
  static const signingTime = '1.2.840.113549.1.9.5';
  static const smimeCapabilities = '1.2.840.113549.1.9.15';
  static const timestamp = '1.2.840.113549.1.9.16.2.14';

  static const Map<HashAlgorithm, List<int>> hashAlgorithmIdentifiers =
      <HashAlgorithm, List<int>>{
    HashAlgorithm.sha1: <int>[1, 3, 14, 3, 2, 26],
    HashAlgorithm.sha256: <int>[2, 16, 840, 1, 101, 3, 4, 2, 1],
    HashAlgorithm.sha384: <int>[2, 16, 840, 1, 101, 3, 4, 2, 2],
    HashAlgorithm.sha512: <int>[2, 16, 840, 1, 101, 3, 4, 2, 3],
  };

  String digestIdentifierHex(HashAlgorithm algorithm) {
    final o = ASN1ObjectIdentifier(Pkcs.hashAlgorithmIdentifiers[algorithm]);
    return o.encode().map((e) => e.toRadixString(16).padLeft(2, '0')).join();
  }

  String toHex(Iterable<int>? list) {
    if (list == null) {
      return '(null)';
    }

    final iter = list.map((e) => e.toRadixString(16).padLeft(2, '0')).toList();
    if (iter.length < 35) {
      return iter.join(':');
    }
    final parts = iter.sublist(0, 20)
      ..add('(...)')
      ..addAll(iter.sublist(max(20, iter.length - 10), iter.length));
    return parts.join(':');
  }

  String padText(String s, int amount) {
    return s
        .replaceAll(RegExp(r'^', multiLine: true), ''.padLeft(amount))
        .trimLeft();
  }

  /// Parse a list of names
  Iterable<MapEntry<ASN1ObjectIdentifier, dynamic>> namesFromAsn1(
      ASN1Sequence sequence) sync* {
    for (final p in sequence.elements!) {
      if (p is ASN1Set) {
        for (final q in p.elements!) {
          if (q is ASN1Sequence) {
            final r = q.elements![0];
            if (r is ASN1ObjectIdentifier) {
              yield MapEntry<ASN1ObjectIdentifier, dynamic>(
                  r, asn1ToDart(q.elements![1]));
            }
          }
        }
      }
    }
  }

  dynamic asn1ToDart(ASN1Object obj) {
    if (obj is ASN1OctetString) {
      return obj.octets;
    }
    if (obj is ASN1PrintableString) {
      return obj.stringValue;
    }
    if (obj is ASN1IA5String) {
      return obj.stringValue;
    }
    if (obj is ASN1UTF8String) {
      return obj.utf8StringValue;
    }
    if (obj is ASN1TeletextString) {
      return obj.stringValue;
    }
    if (obj is ASN1ObjectIdentifier) {
      return obj;
    }
    if (obj is ASN1UtcTime) {
      return obj.time;
    }
    return obj;
  }

  String asn1ToString(dynamic obj) {
    if (obj is ASN1Object) {
      obj = asn1ToDart(obj);
    }

    if (obj is String) {
      return obj;
    }
    if (obj is Uint8List) {
      return toHex(obj);
    }
    if (obj is ASN1ObjectIdentifier) {
      return obj.name;
    }
    if (obj is ASN1Integer) {
      return obj.integer.toString();
    }
    if (obj is ASN1Sequence) {
      return obj.elements?.map<String>((e) => asn1ToString(e)).join(', ') ??
          'empty sequence';
    }

    return obj.toString();
  }

  HashAlgorithm commonDigestAlgorithm(
      ASN1ObjectIdentifier signatureAlgorithmID) {
    switch (signatureAlgorithmID.objectIdentifierAsString) {
      case sha1WithRsaSignature:
      case sha1:
        return HashAlgorithm.sha1;
      case ecdsaWithSha256:
      case sha256:
      case sha256WithRSAEncryption:
        return HashAlgorithm.sha256;
      case ecdsaWithSha384:
      case sha384:
      case sha384WithRSAEncryption:
        return HashAlgorithm.sha384;
      case ecdsaWithSha512:
      case sha512:
      case sha512WithRSAEncryption:
        return HashAlgorithm.sha512;
    }

    throw UnimplementedError(
        'Unsupported signature digest ${signatureAlgorithmID.objectIdentifierAsString}');
  }

  Digest getDigest(HashAlgorithm digestAlgorithm) {
    switch (digestAlgorithm) {
      case HashAlgorithm.sha1:
        return SHA1Digest();
      case HashAlgorithm.sha256:
        return SHA256Digest();
      case HashAlgorithm.sha384:
        return SHA384Digest();
      case HashAlgorithm.sha512:
        return SHA512Digest();
    }
  }

  /// Encode a hash to a DER message
  Uint8List derEncode(Uint8List hash, HashAlgorithm digest) {
    return ASN1Sequence(elements: [
      ASN1Sequence(elements: [
        ASN1ObjectIdentifier(Pkcs.hashAlgorithmIdentifiers[digest]),
        ASN1Null(),
      ]),
      ASN1OctetString(octets: hash),
    ]).encode();
  }

  /// Test if two lists are equal
  bool listEquality(Uint8List f, Uint8List o) {
    if (f.length == o.length) {
      for (var i = 0; i < f.length; i++) {
        if (f[i] != o[i]) {
          return false;
        }
      }
      return true;
    }
    return false;
  }
}

/// ASN1ObjectIdentifier extensions
extension OIName on ASN1ObjectIdentifier {
  /// Get the readable name of this OI
  String get name {
    if (readableName != null) {
      return readableName!;
    }

    const names = <String, String>{
      Pkcs.contentType: 'contentType',
      Pkcs.data: 'data',
      Pkcs.ecdsaWithSha256: 'ecdsaWithSha256',
      Pkcs.ecdsaWithSha384: 'ecdsaWithSha384',
      Pkcs.ecdsaWithSha512: 'ecdsaWithSha512',
      Pkcs.emailAddress: 'emailAddress',
      Pkcs.messageDigest: 'messageDigest',
      Pkcs.netscapeComment: 'netscape-comment',
      Pkcs.organizationIdentifier: 'organizationIdentifier',
      Pkcs.rsaEncryption: 'rsaEncryption',
      Pkcs.sha1: 'sha1',
      Pkcs.sha1WithRsaSignature: 'sha1WithRsaSignature',
      Pkcs.sha256: 'sha256',
      Pkcs.sha256WithRSAEncryption: 'sha256WithRSAEncryption',
      Pkcs.sha384: 'sha384',
      Pkcs.sha384WithRSAEncryption: 'sha384WithRSAEncryption',
      Pkcs.sha512: 'sha512',
      Pkcs.sha512WithRSAEncryption: 'sha512WithRSAEncryption',
      Pkcs.signedData: 'signedData',
      Pkcs.signingTime: 'signingTime',
      Pkcs.smimeCapabilities: 'smimeCapabilities',
      Pkcs.timestamp: 'timestamp',
    };

    if (names[objectIdentifierAsString] == null) {
      print('OI not found: $objectIdentifierAsString');
    }

    return names[objectIdentifierAsString] ??
        objectIdentifierAsString ??
        '(unknown)';
  }
}
