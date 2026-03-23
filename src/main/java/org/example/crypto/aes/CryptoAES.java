package org.example.crypto.aes;

import org.example.crypto.CryptoMode;
import org.example.crypto.Icrypto;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.util.Base64;

public class CryptoAES implements Icrypto {
    private SecretKey key;
    private CryptoMode mode = CryptoMode.ECB; // Mode par défaut
    private byte[] iv; // Pour CBC mode
    private static final String ALGORITHM = "AES";

    public void setMode(CryptoMode mode) {
        this.mode = mode;
    }

    public CryptoMode getMode() {
        return mode;
    }

    private String getTransformation() {
        if (mode == CryptoMode.ECB) {
            return "AES/ECB/PKCS5Padding"; // OAEP est plus sécurisé
        } else {
            return "AES/CBC/PKCS5Padding";
        }
    }

    @Override
    public void genKey(int keySize) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM);
        kg.init(keySize);
        key = kg.generateKey();

        // Si on est en mode CBC, générer un IV (Initialization Vector)
        if (mode == CryptoMode.CBC) {
            SecureRandom random = new SecureRandom();
            iv = new byte[16]; // 16 bytes pour AES
            random.nextBytes(iv);
        }
    }

    @Override
    public String encrypt(String plainText) throws Exception {
        if (key == null) {
            throw new IllegalStateException("Clé non initialisée");
        }

        Cipher cipher = Cipher.getInstance(getTransformation());

        if (mode == CryptoMode.CBC) {
            // Si pas d'IV généré, en créer un nouveau
            if (iv == null) {
                SecureRandom random = new SecureRandom();
                iv = new byte[16];
                random.nextBytes(iv);
            }
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, key);
        }

        byte[] encrypted = cipher.doFinal(plainText.getBytes("UTF-8"));

        // Pour CBC, on peut préfixer l'IV au texte chiffré
        if (mode == CryptoMode.CBC) {
            // Concaténer IV + données chiffrées
            byte[] combined = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);
            return Base64.getEncoder().encodeToString(combined);
        }

        return Base64.getEncoder().encodeToString(encrypted);
    }

    @Override
    public String decrypt(String cipherText) throws Exception {
        if (key == null) {
            throw new IllegalStateException("Clé non initialisée");
        }

        Cipher cipher = Cipher.getInstance(getTransformation());
        byte[] decoded = Base64.getDecoder().decode(cipherText);

        if (mode == CryptoMode.CBC) {
            // Extraire l'IV des données
            byte[] ivExtracted = new byte[16];
            byte[] encryptedData = new byte[decoded.length - 16];

            System.arraycopy(decoded, 0, ivExtracted, 0, 16);
            System.arraycopy(decoded, 16, encryptedData, 0, encryptedData.length);

            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivExtracted));
            return new String(cipher.doFinal(encryptedData), "UTF-8");
        } else {
            cipher.init(Cipher.DECRYPT_MODE, key);
            return new String(cipher.doFinal(decoded), "UTF-8");
        }
    }

    // Méthodes pour gérer l'IV (utile si vous voulez le sauvegarder séparément)
    public byte[] getIV() {
        return iv;
    }

    public void setIV(byte[] iv) {
        this.iv = iv;
    }

    // Version pour sauvegarder l'IV en base64
    public void saveIV(File file) throws Exception {
        if (iv == null) {
            throw new IllegalStateException("IV non initialisé");
        }
        Files.writeString(file.toPath(),
                Base64.getEncoder().encodeToString(iv));
    }

    public void loadIV(File file) throws Exception {
        String content = Files.readString(file.toPath()).trim();
        iv = Base64.getDecoder().decode(content);
    }

    @Override
    public void saveKey(File file) throws Exception {
        if (key == null) {
            throw new IllegalStateException("Aucune clé à sauvegarder");
        }

        Files.writeString(
                file.toPath(),
                Base64.getEncoder().encodeToString(key.getEncoded())
        );
    }

    @Override
    public void loadKey(File file) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(Files.readString(file.toPath()));
        key = new SecretKeySpec(decoded, ALGORITHM);
    }

    @Override
    public void saveText(String text, File file) throws Exception {
        Files.writeString(file.toPath(), text);
    }

    @Override
    public String loadText(File file) throws Exception {
        return Files.readString(file.toPath());
    }

    public String getKeyAsBase64() {
        if (key == null) return "";
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }
}