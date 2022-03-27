import 'package:encription_dart_js/encription_dart_js.dart' as en;

void main(List<String> arguments) {
  String d = en.decryptAESCryptoJS(
      encrypted: 'U2FsdGVkX1/5/QyqowjjI7UJksazXJTEEuk/0u5Pnck=',
      passphrase: 'secret key 123');
  print(d);
}
