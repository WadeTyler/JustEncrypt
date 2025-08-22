# JustEncrypt
JustEncrypt is a simple and secure encryption tool that allows you to encrypt and decrypt files using a key. It uses the AES-256 encryption algorithm to ensure your data is protected.

## Quick Start
### 1. Add the required dependency to your pom.xml:
```xml
<dependency>
    <groupId>net.tylerwade</groupId>
    <artifactId>just-encrypt</artifactId>
    <version>1.0.0</version>
</dependency>
```

### 3. Add Encryption Key  
To add an encryption key, you either add the encryption to the constructor of the `JustEncrypt` class or set it via Environmental variable. NOTE: If you do not set an encryption key, an encryption key will be auto generated, but will not persist across runs.

#### Constructor Example:
```java
SecretKey secretKey = KeyGenerator.getInstance("AES").generateKey();
JustEncrypt justEncrypt = new JustEncrypt(secretKey);
```

#### Environmental Variable Example:
```
JUST_ENCRYPT_KEY=your_secret_key_here
```

### 2. Use the `JustEncrypt` class to encrypt and decrypt data.

### Encrypting Data
Encryption can be done with the persisted key, or you can encrypt with a different key each time.
```java
String encryptedString = justEncrypt.encrypt("Sample Data");
```
or
```java
String encryptedString = justEncrypt.encrypt("Sample Data", secretKey);
```

### Decrypting Data
Decryption can be done with the persisted key, or you can decrypt with a different key each time.
```java
String decryptedString = justEncrypt.decrypt(encryptedString);
```
or
```java
String decryptedString = justEncrypt.decrypt(encryptedString, secretKey);
```