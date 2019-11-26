import java.security.*;
import javax.crypto.*;

import org.bouncycastle.jce.provider.*;

/**
 *
 * <p>
 * Title: RSAEncryptUtil
 * </p>
 * <p>
 * Description: Utility class that helps encrypt and decrypt strings using RSA
 * algorithm
 * </p>
 * 
 * @author Aviran Mordo http://aviran.mordos.com
 * @version 1.0
 */
public class RSAEncryptUtil {
    protected static final String ALGORITHM = "RSA";

    public RSAEncryptUtil() {
        init();
    }

    /**
     * Init java security to add BouncyCastle as an RSA provider
     */
    public static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Generate key which contains a pair of privae and public key using 1024 bytes
     * 
     * @return key pair
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static KeyPair generateKey() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
        keyGen.initialize(1024);
        KeyPair key = keyGen.generateKeyPair();
        return key;
    }

    /**
     * Encrypt a text using public key.
     * 
     * @param text The original unencrypted text
     * @param key  The public key
     * @return Encrypted text
     * @throws java.lang.Exception
     */
    public static byte[] encrypt(byte[] text, PublicKey key) throws Exception {
        byte[] cipherText = null;

        // get an RSA cipher object and print the provider
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", BouncyCastleProvider.PROVIDER_NAME);

        // encrypt the plaintext using the public key
        cipher.init(Cipher.ENCRYPT_MODE, key);
        cipherText = cipher.doFinal(text);
        return cipherText;
    }

    /**
     * Encrypt a text using public key. The result is enctypted BASE64 encoded text
     * 
     * @param text The original unencrypted text
     * @param key  The public key
     * @return Encrypted text encoded as BASE64
     * @throws java.lang.Exception
     */
    public static String encrypt(String text, PublicKey key) throws Exception {
        String encryptedText;
        byte[] cipherText = encrypt(text.getBytes("UTF8"), key);
        encryptedText = byteArrayToHex(cipherText);
        return encryptedText;
    }

    /**
     * Decrypt text using private key
     * 
     * @param text The encrypted text
     * @param key  The private key
     * @return The unencrypted text
     * @throws java.lang.Exception
     */
    public static byte[] decrypt(byte[] text, PrivateKey key) throws Exception {
        byte[] dectyptedText = null;
        // decrypt the text using the private key
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.DECRYPT_MODE, key);
        dectyptedText = cipher.doFinal(text);
        return dectyptedText;

    }

    public static String byteArrayToHex(byte[] ba) {
        if (ba == null || ba.length == 0)
            return null;

        StringBuffer sb = new StringBuffer(ba.length * 2);
        String hexNumber;

        for (int x = 0; x < ba.length; x++) {
            hexNumber = "0" + Integer.toHexString(0xff & ba[x]);
            sb.append(hexNumber.substring(hexNumber.length() - 2));
        }

        return sb.toString();
    }

}