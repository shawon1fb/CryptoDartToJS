import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:pointycastle/export.dart';
import 'package:crypto/crypto.dart';

class AES256 {
  final Uint8List key;
  final Uint8List iv;

  AES256(this.key, this.iv) {
    if (key.length != 32) {
      throw Exception('Bad key length');
    }

    if (iv.length != 16) {
      throw Exception('Bad input vector length');
    }
  }

  Uint8List encrypt(String data) {
    final cipher = PaddedBlockCipherImpl(
      PKCS7Padding(),
      CBCBlockCipher(AESFastEngine()),
    );

    cipher.init(true, PaddedBlockCipherParameters(
        ParametersWithIV(KeyParameter(key), iv), null
    ));

    final encodedData = Uint8List.fromList(utf8.encode(data));
    return cipher.process(encodedData);
  }

  String decrypt(Uint8List data) {
    final cipher = PaddedBlockCipherImpl(
      PKCS7Padding(),
      CBCBlockCipher(AESFastEngine()),
    );

    cipher.init(false, PaddedBlockCipherParameters(
        ParametersWithIV(KeyParameter(key), iv), null
    ));

    final decryptedData = cipher.process(data);
    return utf8.decode(decryptedData);
  }

  static Uint8List createKey(String password, Uint8List salt) {
    final keyDerivator = KeyDerivator('SHA-1/HMAC/PBKDF2')
      ..init(Pbkdf2Parameters(salt, 10000, 32));
    return keyDerivator.process(Uint8List.fromList(utf8.encode(password)));
  }

  static Uint8List randomIv() {
    final secureRandom = SecureRandom('AES/CTR/AUTO-SEED-PRNG');
    final random = Random.secure();
    final seeds = Uint8List(32);
    for (var i = 0; i < 32; i++) {
      seeds[i] = random.nextInt(256);
    }
    secureRandom.seed(KeyParameter(seeds));
    return secureRandom.nextBytes(16);
  }

  static Uint8List iV() {
    return Uint8List.fromList([
      0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01,
      0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01,
    ]);
  }

  static Uint8List randomSalt() {
    final secureRandom = SecureRandom('AES/CTR/AUTO-SEED-PRNG');
    return secureRandom.nextBytes(8);
  }
}

class AppTimeBaseEncryption {

  static String generateKey(String secret) {
    const period = 120;
    const digits = 32;
    final secretBytes = utf8.encode(secret);
    final counter = (DateTime.now().millisecondsSinceEpoch ~/ 1000) ~/ period;
    final counterBytes = ByteData(8)..setInt64(0, counter, Endian.big);
    final hmac = Hmac(sha1, secretBytes);
    final hash = hmac.convert(counterBytes.buffer.asUint8List());

    final offset = hash.bytes.last & 0x0f;
    final truncatedHashBytes = hash.bytes.sublist(offset, offset + 4);
    var truncatedHash = ByteData.sublistView(Uint8List.fromList(truncatedHashBytes));
    final intHashValue = truncatedHash.getUint32(0, Endian.big) & 0x7FFFFFFF;

    final key = intHashValue.toString().padLeft(digits, '0');
    // print("Generated key => $key");
    return key;
  }

  static String secureEncryptSecretText(String planeText, String secret) {
    String key = generateKey(secret);
    final keyData = utf8.encode(key);
    final iv = randomIv();
    Uint8List bytes = Uint8List.fromList(keyData);
    final aes = AES256(bytes, iv);
    final encryptedData = aes.encrypt(planeText);
    final ivBase64 = base64.encode(iv);
    final encryptedBase64 = base64.encode(encryptedData);
    final encryptedString = '$ivBase64:$encryptedBase64';
    return encryptedString;
  }

  static String? decryptEncryptedText(String encryptedString, String secret) {
    // String key = "00000000000000000000000400514365";//generateKey(secret);
    String key = generateKey(secret);
    // print("key $key");
    final keyData = utf8.encode(key);
    final substrings = encryptedString.split(':');
    final ivString = substrings.first;
    final dataString = substrings.last;

    final iv = base64.decode(ivString);
    final encryptedData = base64.decode(dataString);
    Uint8List bytes = Uint8List.fromList(keyData);
    final aes = AES256(bytes, iv);
    final decryptedData = aes.decrypt(Uint8List.fromList(encryptedData));
    final decryptedString = decryptedData;

    return decryptedString;
  }

  static Uint8List randomIv() {
    final random = Random.secure();
    final iv = Uint8List(16);
    for (var i = 0; i < iv.length; i++) {
      iv[i] = random.nextInt(256);
    }
    return iv;
  }
}

void main(){
  var planeText = "jnzjcvawelqnwehxcvuaesdkcves";
  var encriptionServerToken = "7c93f2820d8248a01323c3813ef4e8d734bc4afc";
  String v = AppTimeBaseEncryption.secureEncryptSecretText(encriptionServerToken, planeText);
  print(v);
}
