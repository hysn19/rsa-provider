# rsa-provider
rsa-provider java proejct


```java
String plaintext = "Hello, RSA Algorithm";

Security.addProvider(new BouncyCastleProvider());

// Create the public and private keys
// KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA",
// BouncyCastleProvider.PROVIDER_NAME);

// SecureRandom random = createFixedRandom();
// generator.initialize(1024, random);

// KeyPair pair = generator.generateKeyPair();
// PublicKey pubKey = pair.getPublic();
// PrivateKey privKey = pair.getPrivate();

byte[] priKeyBytes = hexToByteArray(                "30820277020100300d06092a864886f70d0101010500048202613082025d02010002818100e941eb043129395ca6b4908d0ab8d047984e3a4996763da75ab11914b5c99d94ae3ddc9c13fa53eedc452a742d8565819dba7127b9dd519357b3e53eb0bc5286979d3808b2958f81346da03ad87d091de0e2650bc318100c0ea2e1f936fa9848f6a845579368d532a5640e090cb7f3977e94f525031b3b225ac5b3c1d033e09302030100010281801f9b738da35dbb2c9f584b58195256c2c4d420d8d4df1bd6a016ec579e947dda664bf2a7619ba3a0f3cf198419a10052b27d4f94fafe0eee40cd9b2c460596c6ece97ba407abbab04d05b842182dc3d6b45e8ba676a48b527e0d034e72fb8a399a8ab6817b2658d0283aac9a04c9c9cbcb886719a3497f3fca1e957c0746b885024100f9e9d731e5a0a848bc548550e73585075f7f9099e02458d05911e143eb0adea5f468ba1acbb99ece8a2867868e17022bbc65ab1c3b8618a208a6d3b5b1c3316f024100eef03b21f91568f130129c6586cbb3deb0a06b2aeb7fc2636870673f664187e079a080b96ca37eca5af22cbcf1ea0be1c483972cbafb2e99b4f905a6315ba91d024100ab2f050b95a9dd7bad1d0c10a5bf203733aff281a469e1381dbac49dbc333edd5834203e588bf5feadde0d43bab281f7295e4ebdd0fc028582fd9b08db11c41b024100d474750fdb2bc75915f6a66bbbf4aaa5eb0568e50beb58cc0d544ce9d9a19110eef4e1207ed1cd6e5e7991801bd690e419592c759078c1d1d851c84d22fc2e9d024062493deb105da22b3522a4c5d7574eaced71279f7bac46544c9d4da71a1b3056f1899a5a6b12d3d8452647929abe7ddea0eb8e2fa18f1c48dbc91290c75b5c6c");
byte[] pubKeyBytes = hexToByteArray(                "30819f300d06092a864886f70d010101050003818d0030818902818100e941eb043129395ca6b4908d0ab8d047984e3a4996763da75ab11914b5c99d94ae3ddc9c13fa53eedc452a742d8565819dba7127b9dd519357b3e53eb0bc5286979d3808b2958f81346da03ad87d091de0e2650bc318100c0ea2e1f936fa9848f6a845579368d532a5640e090cb7f3977e94f525031b3b225ac5b3c1d033e0930203010001");
KeyFactory kf = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
PrivateKey priKey = kf.generatePrivate(new PKCS8EncodedKeySpec(priKeyBytes));
PublicKey pubKey = kf.generatePublic(new X509EncodedKeySpec(pubKeyBytes));

Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", BouncyCastleProvider.PROVIDER_NAME);

cipher.init(Cipher.ENCRYPT_MODE, pubKey);
byte[] cipherBytes = cipher.doFinal(plaintext.getBytes());

cipher.init(Cipher.DECRYPT_MODE, priKey);
byte[] plainBytes = cipher.doFinal(cipherBytes);

```
