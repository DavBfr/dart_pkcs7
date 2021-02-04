import 'dart:typed_data';

import 'package:pointycastle/asn1.dart';

import 'common.dart';

/// Manage Pkcs Timestamping
class TimestampResponse with Pkcs {
  /// Creates a Timestamp from an [ASN1Sequence].
  const TimestampResponse(this._asn1);

  /// Creates a Timestamp from DER encoded bytes.
  factory TimestampResponse.fromDer(Uint8List der) => TimestampResponse(
        ASN1Parser(der).nextObject() as ASN1Sequence,
      );

  final ASN1Sequence _asn1;

  /// ASN1 object representing the Timestamp Response
  ASN1Sequence get asn1 => _asn1;

  /// DER representation of the Timestamp
  Uint8List get der => _asn1.encodedBytes!;

  /// ASN1 object representing the timeStampToken
  ASN1Sequence get timeStampToken {
    return _asn1.elements![1] as ASN1Sequence;
  }

  /// Generate a TS request message
  static Uint8List generateRequest(
    HashAlgorithm digestAlgorithm,
    Uint8List digest,
  ) {
    final ts = ASN1Sequence(elements: [
      ASN1Integer.fromtInt(1),
      ASN1Sequence(elements: [
        ASN1Sequence(elements: [
          ASN1ObjectIdentifier(Pkcs.hashAlgorithmIdentifiers[digestAlgorithm]),
          ASN1Null(),
        ]),
        ASN1OctetString(octets: digest),
      ]),
      ASN1Boolean(true),
    ]);

    return ts.encode();
  }
}
