import 'dart:typed_data';

import 'package:pem/pem.dart';
import 'package:pointycastle/asn1.dart';

import 'common.dart';
import 'crl.dart';
import 'pkcs7_signer_info.dart';
import 'x509.dart';

/// A Pkcs7 Message
class Pkcs7 with Pkcs {
  /// Creates a Pkcs7 message from an [ASN1Sequence].
  factory Pkcs7(ASN1Sequence asn1) {
    final data =
        ASN1Parser(asn1.elements![1].valueBytes).nextObject() as ASN1Sequence;

    ASN1Object? cert;

    ASN1Object? crl;

    ASN1Set? signerInfo;

    for (final e in data.elements!.sublist(3)) {
      if (e.tag == 0xa0) {
        cert = e;
      } else if (e.tag == 0xa1) {
        crl = e;
      } else if (e is ASN1Set) {
        signerInfo = e;
      }
    }

    final pkcs7 = Pkcs7._(asn1, data, cert, crl, signerInfo);

    if (pkcs7.contentType.objectIdentifierAsString != Pkcs.signedData) {
      throw UnsupportedError(
          'Not a Pkcs7 signature message (${pkcs7.contentType.objectIdentifierAsString})');
    }

    return pkcs7;
  }

  const Pkcs7._(
    this._asn1,
    this._data,
    this._cert,
    this._crl,
    this._signerInfo,
  );

  /// Creates a Pkcs7 message from DER encoded bytes.
  factory Pkcs7.fromDer(Uint8List der) => Pkcs7(
        ASN1Parser(der).nextObject() as ASN1Sequence,
      );

  /// Creates a Pkcs7 message from a PEM encoded string.
  factory Pkcs7.fromPem(String pem) => Pkcs7.fromDer(
        Uint8List.fromList(PemCodec(PemLabel.pkcs7).decode(pem)),
      );

  final ASN1Sequence _asn1;

  final ASN1Sequence _data;

  final ASN1Object? _cert;

  final ASN1Object? _crl;

  final ASN1Set? _signerInfo;

  /// ASN1 object representing the Pkcs7 message
  ASN1Sequence get asn1 => _asn1;

  /// DER representation of the Pkcs7 message
  Uint8List get der => _asn1.encodedBytes!;

  /// PEM representation of the Pkcs7 message
  String get pem => PemCodec(PemLabel.pkcs7).encode(der);

  /// Message type
  ASN1ObjectIdentifier get contentType {
    return _asn1.elements![0] as ASN1ObjectIdentifier;
  }

  /// The version number of the message.
  int get version {
    final ver = _data.elements![0] as ASN1Integer;
    return ver.integer!.toInt();
  }

  /// The signature Algorithm ID of the message.
  Iterable<ASN1ObjectIdentifier> get digestAlgorithms sync* {
    final algos = _data.elements![1] as ASN1Set;
    for (final algo in algos.elements!) {
      final algoSeq = algo as ASN1Sequence;
      yield algoSeq.elements![0] as ASN1ObjectIdentifier;
    }
  }

  /// Encapsulated message content type
  ASN1ObjectIdentifier get encapsulatedContentType {
    final content = _data.elements![2] as ASN1Sequence;
    return content.elements![0] as ASN1ObjectIdentifier;
  }

  /// Encapsulated message content
  Uint8List? get encapsulatedContent {
    final content = _data.elements![2] as ASN1Sequence;
    if (content.elements!.length > 1) {
      final eContent = content.elements![1] as ASN1OctetString;
      return eContent.octets!;
    }
    return null;
  }

  /// The certification chain of the message.
  Iterable<X509> get certificates sync* {
    if (_cert == null) {
      return;
    }

    var o = 0;
    while (o < _cert!.valueByteLength!) {
      final c = ASN1Parser(_cert!.valueBytes!.sublist(o)).nextObject();
      yield X509(c as ASN1Sequence);
      o += c.encodedBytes!.lengthInBytes;
    }
  }

  /// The certificate revocation lists of the message.
  Iterable<CertificateRevocationList> get crls sync* {
    if (_crl == null) {
      return;
    }

    var o = 0;
    while (o < _crl!.valueByteLength!) {
      final c = ASN1Parser(_crl!.valueBytes!.sublist(o)).nextObject();
      yield CertificateRevocationList(c as ASN1Sequence);
      o += c.encodedBytes!.lengthInBytes;
    }
  }

  /// List of Pkcs7 message signatures.
  Iterable<Pkcs7SignerInfo> get signerInfo sync* {
    if (_signerInfo == null) {
      return;
    }

    for (final e in _signerInfo!.elements!) {
      yield Pkcs7SignerInfo(e as ASN1Sequence);
    }
  }

  /// Verify the Pkcs7 validity against a list of trusted certificates
  /// and returns the validated signature
  Pkcs7SignerInfo verify(List<X509> trusted) {
    if (contentType.objectIdentifierAsString != Pkcs.signedData) {
      throw Exception(
          'Invalid Pkcs7 message type: ${contentType.objectIdentifierAsString}');
    }

    final certs = certificates.toList();

    // One signature should match
    for (final si in signerInfo) {
      if (si.signatureAlgorithmID.objectIdentifierAsString !=
          Pkcs.rsaEncryption) {
        continue;
      }

      try {
        final algo = si.digestAlgorithm;
        final sign = si.signature;
        final message = ASN1Set(
                elements: si.signedAttributes
                    .map((e) => ASN1Sequence(
                          elements: [
                            e.key,
                            ASN1Set(elements: e.value),
                          ],
                        ))
                    .toList())
            .encode();

        for (final cert in certs) {
          if (cert.verifySignature(sign, message, algo)) {
            cert.verifyChain(certs, trusted);
            return si;
          }
        }
      } catch (e) {
        print('Error: $e');
      }
    }

    throw Exception('Unable to validate the message signature');
  }

  @override
  String toString() {
    final b = StringBuffer();
    b.writeln('$runtimeType');
    b.writeln('  Content Type: ${contentType.name}');
    b.writeln('  Version: $version');
    b.writeln('  Algorithms:');
    for (final algo in digestAlgorithms) {
      b.writeln('    - ${algo.name}');
    }
    b.writeln('  Content:');
    b.writeln('    Type: ${encapsulatedContentType.name}');
    b.writeln('    Value: ${toHex(encapsulatedContent)}');
    b.writeln('  Certificates:');
    for (final cert in certificates) {
      b.writeln('    - ${padText(cert.toString(), 6)}');
    }
    b.writeln('  Signer Infos:');
    for (final si in signerInfo) {
      b.writeln('    - ${padText(si.toString(), 6)}');
    }
    return b.toString();
  }
}
