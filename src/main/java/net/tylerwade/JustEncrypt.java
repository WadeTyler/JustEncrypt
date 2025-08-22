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

/**
 * JustEncrypt is a simple utility class for encrypting and decrypting strings using AES encryption.
 */
public class JustEncrypt {
    // Encryption key first check for use in constructor, if one is not provided,
    // it will then check for a key in environment variables as "JUST_ENCRYPT_KEY".
    // If no key is found, it will generate a new key and print it to the console.
    private SecretKey encryptionKey;
    private static final EncryptionUtil encryptionUtil = new EncryptionUtil();

    /**
     * Default constructor that checks for an encryption key in the environment variables.
     */
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

    /**
     * Constructor that accepts a SecretKey for encryption and decryption.
     * @param encryptionKey The SecretKey to use for encryption and decryption.
     */
    public JustEncrypt(SecretKey encryptionKey) {
        this.encryptionKey = encryptionKey;
    }

    /**
     * Constructor that accepts a Base64 encoded string as the encryption key.
     * @param data The Base64 encoded string to use as the encryption key.
     * @return The encrypted string.
     * @throws IllegalBlockSizeException
     * @throws NoSuchPaddingException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public String encrypt(String data) throws IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        return encryptionUtil.encrypt(data, encryptionKey);
    }

    /**
     * Encrypts the given data using the provided SecretKey.
     * @param data The data to encrypt.
     * @param key The SecretKey to use for encryption.
     * @return The encrypted string.
     * @throws IllegalBlockSizeException
     * @throws NoSuchPaddingException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public String encrypt(String data, SecretKey key) throws IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        return encryptionUtil.encrypt(data, key);
    }

    /**
     * Decrypts the given encrypted data using the stored encryption key.
     * @param encryptedData The encrypted data to decrypt.
     * @return The decrypted string.
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws NoSuchAlgorithmException
     * @throws BadPaddingException
     * @throws InvalidKeyException
     */
    public String decrypt(String encryptedData) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        return encryptionUtil.decrypt(encryptedData, encryptionKey);
    }

    /**
     * Decrypts the given encrypted data using the provided SecretKey.
     * @param encryptedData The encrypted data to decrypt.
     * @param key The SecretKey to use for decryption.
     * @return The decrypted string.
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws NoSuchAlgorithmException
     * @throws BadPaddingException
     * @throws InvalidKeyException
     */
    public String decrypt(String encryptedData, SecretKey key) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        return encryptionUtil.decrypt(encryptedData, key);
    }

    /**
     * Generates a new random SecretKey for AES encryption.
     * @return The generated SecretKey.
     * @throws NoSuchAlgorithmException if the AES algorithm is not available.
     */
    public SecretKey generateRandomKey() throws NoSuchAlgorithmException {
        return encryptionUtil.generateKey();
    }


}