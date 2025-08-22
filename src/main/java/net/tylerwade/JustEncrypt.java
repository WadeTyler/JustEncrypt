package net.tylerwade;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class JustEncrypt {
    // Encryption key first check for use in constructor, if one is not provided,
    // it will then check for a key in environment variables as "JUST_ENCRYPT_KEY".
    // If no key is found, it will generate a new key and print it to the console.
    private SecretKey encryptionKey;
    private static final EncryptionUtil encryptionUtil = new EncryptionUtil();

    public JustEncrypt() {
        // Check for key in environment variables
        String envKey = System.getenv("JUST_ENCRYPT_KEY");
        if (envKey != null && !envKey.isBlank()) {
            byte[] keyBytes = Base64.getDecoder().decode(envKey);
            this.encryptionKey = new SecretKeySpec(keyBytes, "AES");
            return;
        }

        // Generate a new key if none is provided
        try {
            SecretKey generatedKey = encryptionUtil.generateKey();
            this.encryptionKey = generatedKey;
            String base64Key = Base64.getEncoder().encodeToString(generatedKey.getEncoded());
            System.out.println("================= net.tylerwade.JustEncrypt Key =================");
            System.out.println("No encryption key provided. Generated new key:");
            System.out.println("Base64 Encoded Key: " + base64Key);
            System.out.println("If you do not provide this key in the environment variable JUST_ENCRYPT_KEY or provide it to JustEncrypt, you will not be able to decrypt any previously encrypted data.");
            System.out.println("===================================================");
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to generate encryption key.", e);
        }
    }

    public JustEncrypt(SecretKey encryptionKey) {
        this.encryptionKey = encryptionKey;
    }

    public String encrypt(String data) throws IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        return encryptionUtil.encrypt(data, encryptionKey);
    }

    public String encrypt(String data, SecretKey key) throws IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        return encryptionUtil.encrypt(data, key);
    }

    public String decrypt(String encryptedData) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        return encryptionUtil.decrypt(encryptedData, encryptionKey);
    }

    public String decrypt(String encryptedData, SecretKey key) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        return encryptionUtil.decrypt(encryptedData, key);
    }

    public SecretKey generateRandomKey() throws NoSuchAlgorithmException {
        return encryptionUtil.generateKey();
    }


}