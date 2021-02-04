import 'dart:typed_data';

import 'package:pem/pem.dart';
import 'package:pointycastle/asn1.dart';

import 'common.dart';

/// Manage Pkcs Certificate Revocation List
class CertificateRevocationList with Pkcs {
  /// Creates a Certificate Revocation List from an [ASN1Sequence].
  const CertificateRevocationList(this._asn1);

  /// Creates a Certificate Revocation List from DER encoded bytes.
  factory CertificateRevocationList.fromDer(Uint8List der) =>
      CertificateRevocationList(
        ASN1Parser(der).nextObject() as ASN1Sequence,
      );

  /// Creates a Certificate Revocation List from a PEM encoded string.
  factory CertificateRevocationList.fromPem(String pem) =>
      CertificateRevocationList.fromDer(
        Uint8List.fromList(
            PemCodec(PemLabel.certificateRevocationList).decode(pem)),
      );

  final ASN1Sequence _asn1;

  /// ASN1 object representing the Certificate Revocation List
  ASN1Sequence get asn1 => _asn1;

  /// DER representation of the Certificate Revocation List
  Uint8List get der => _asn1.encodedBytes!;
}
