import 'dart:typed_data';

import 'package:pem/pem.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/asymmetric/api.dart';
import 'package:pointycastle/asymmetric/pkcs1.dart';
import 'package:pointycastle/asymmetric/rsa.dart';

import 'common.dart';
import 'x509_tbs.dart';

/// An X.509 Certificate
class X509 extends X509Tbs {
  /// Creates a certificate from an [ASN1Sequence].
  factory X509(ASN1Sequence asn1) {
    final tbs = asn1.elements![0] as ASN1Sequence;
    return X509._(asn1, tbs);
  }

  X509._(this._asn1, ASN1Sequence tbs) : super(tbs);

  /// Creates a X.509 Certificate from DER encoded bytes.
  factory X509.fromDer(Uint8List der) => X509(
        ASN1Parser(der).nextObject() as ASN1Sequence,
      );

  /// Creates a certificate from a PEM encoded string.
  factory X509.fromPem(String pem) => X509.fromDer(
        Uint8List.fromList(
          PemCodec(PemLabel.certificate).decode(pem),
        ),
      );

  final ASN1Sequence _asn1;

  /// The X509 certificate asn1 object
  @override
  ASN1Sequence get asn1 => _asn1;

  /// DER representation of the X509 certificate
  Uint8List get der => _asn1.encodedBytes!;

  /// PEM representation of the X509 certificate
  String get pem => PemCodec(PemLabel.certificate).encode(der);

  /// The certificate signature algorithm
  ASN1ObjectIdentifier get signatureAlgorithmOI {
    final sig = _asn1.elements![1] as ASN1Sequence;
    return sig.elements![0] as ASN1ObjectIdentifier;
  }

  /// The parameters for the certificate signature
  ASN1Object get signatureParameters {
    final sig = _asn1.elements![1] as ASN1Sequence;
    return sig.elements![1];
  }

  /// The certificate signature
  Uint8List get signatureValue {
    final sig = _asn1.elements![2] as ASN1BitString;
    return sig.valueBytes!;
  }

  /// Verify the validity of a signature
  bool verifySignature(
    Uint8List signature,
    Uint8List message,
    HashAlgorithm digestAlgorithm,
  ) {
    // Get the hash for the message
    final digest = getDigest(digestAlgorithm);
    final hash = digest.process(message);

    return verifySignatureOfHash(signature, hash, digestAlgorithm);
  }

  /// Verify the validity of a signature
  bool verifySignatureOfHash(
    Uint8List signature,
    Uint8List hash,
    HashAlgorithm digestAlgorithm,
  ) {
    // Decrypt the signature and remove the PKCS1 padding
    final param = PublicKeyParameter<RSAPublicKey>(publicKey);
    final rsa = PKCS1Encoding(RSAEngine());
    rsa.init(false, param);
    final Uint8List sig;
    try {
      sig = rsa.process(signature);
    } catch (_) {
      return false;
    }

    // Expected encoded hash bytes
    final expected = derEncode(hash, digestAlgorithm);

    if (sig.length == expected.length) {
      for (var i = 0; i < sig.length; i++) {
        if (sig[i] != expected[i]) {
          return false;
        }
      }
      return true;
    } else if (sig.length == expected.length - 2) {
      // NULL left out
      final sigOffset = sig.length - hash.length - 2;
      final expectedOffset = expected.length - hash.length - 2;

      expected[1] -= 2; // adjust lengths
      expected[3] -= 2;

      var nonEqual = 0;

      for (var i = 0; i < hash.length; i++) {
        nonEqual |= sig[sigOffset + i] ^ expected[expectedOffset + i];
      }

      for (var i = 0; i < sigOffset; i++) {
        nonEqual |= sig[i] ^ expected[i]; // check header less NULL
      }

      return nonEqual == 0;
    } else {
      return false;
    }
  }

  /// Generate a signature for the message
  Uint8List generateSignature(
    RSAPrivateKey privateKey,
    Uint8List message,
    HashAlgorithm digestAlgorithm,
  ) {
    // Get the hash for the message
    final digest = getDigest(digestAlgorithm);
    final hash = digest.process(message);

    return generateSignatureOfHash(privateKey, hash, digestAlgorithm);
  }

  /// Generate a signature for the message
  Uint8List generateSignatureOfHash(
    RSAPrivateKey privateKey,
    Uint8List hash,
    HashAlgorithm digestAlgorithm,
  ) {
    // Encode the hash
    final encodedHash = derEncode(hash, digestAlgorithm);

    // Encrypt the hash with PKCS1 padding
    final param = PrivateKeyParameter<RSAPrivateKey>(privateKey);
    final rsa = PKCS1Encoding(RSAEngine());
    rsa.init(true, param);
    return rsa.process(encodedHash);
  }

  /// Verify the certificate
  void verify(X509 issuer) {
    final now = DateTime.now();

    if (now.compareTo(notAfter) > 0) {
      throw Exception('Certificate expired: $notAfter');
    }

    if (now.compareTo(notBefore) < 0) {
      throw Exception('Certificate not yet valid: $notBefore');
    }

    issuer.verifySignature(
      signatureValue,
      body,
      digestAlgorithm,
    );
  }

  /// Verify the full certification chain and returns it
  List<X509> verifyChain(
    List<X509> chain,
    List<X509> trusted,
  ) {
    if (trusted.contains(this)) {
      return [this];
    }

    for (final intermediate in chain) {
      try {
        verify(intermediate);
        return [
          this,
          ...intermediate.verifyChain(
            chain.where((e) => e != intermediate).toList(),
            trusted,
          ),
        ];
        // ignore: empty_catches
      } catch (e) {}
    }

    for (final ca in trusted) {
      try {
        verify(ca);
        return [this, ca];
        // ignore: empty_catches
      } catch (e) {}
    }

    throw Exception('No trusted certification chain found');
  }

  @override
  bool operator ==(Object other) {
    if (other is X509) {
      return listEquality(fingerprint, other.fingerprint);
    }

    return false;
  }

  @override
  int get hashCode => fingerprint.reduce((a, b) => a + b);

  @override
  String toString() {
    final b = StringBuffer();
    b.write(super.toString());
    b.writeln('  Signature:');
    b.writeln('    Algorithm: ${signatureAlgorithmOI.name}');
    b.writeln('    Signature: ${toHex(signatureValue)}');
    return b.toString();
  }
}
