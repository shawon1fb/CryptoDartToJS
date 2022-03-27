import 'package:encription_dart_js/encription_dart_js.dart' as en;

void main(List<String> arguments) {
  String d = en.decryptAESCryptoJS(
      encrypted: 'U2FsdGVkX1/5yryGaKLlSZ2q/7nfMu3BQKSv5V62I4s=',
      passphrase: 'secret key 123');
  print(d);
}
