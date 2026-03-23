package org.example.crypto.rsa;

import org.example.crypto.CryptoMode;
import org.example.crypto.Icrypto;

import javax.crypto.Cipher;
import java.io.File;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class CryptoRSA implements Icrypto {
    private KeyPair keyPair;
    private PublicKey publicKeyOnly;  // Pour charger uniquement la clé publique
    private PrivateKey privateKeyOnly; // Pour charger uniquement la clé privée
    private CryptoMode mode = CryptoMode.ECB; // Mode par défaut
    private static final String ALGORITHM = "RSA";

    public void setMode(CryptoMode mode) {
        this.mode = mode;
    }

    public CryptoMode getMode() {
        return mode;
    }

    private String getTransformation() {
        // RSA/ECB/PKCS1Padding est le standard
        // Note: RSA n'utilise pas vraiment ECB/CBC de la même manière qu'AES
        // mais on peut utiliser différents modes de padding
        if (mode == CryptoMode.CBC) {
            return "RSA/ECB/OAEPPadding"; // OAEP est plus sécurisé
        } else {
            return "RSA/ECB/PKCS1Padding";
        }
    }

    @Override
    public void genKey(int keySize) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM);
        kpg.initialize(keySize);
        keyPair = kpg.generateKeyPair();
    }

    @Override
    public String encrypt(String plainText) throws Exception {
        PublicKey pubKey = getPublicKey();
        if (pubKey == null) {
            throw new IllegalStateException("Aucune clé publique disponible");
        }

        Cipher cipher = Cipher.getInstance(getTransformation());
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
    }

    @Override
    public String decrypt(String cipherText) throws Exception {
        PrivateKey privKey = getPrivateKey();
        if (privKey == null) {
            throw new IllegalStateException("Aucune clé privée disponible");
        }

        Cipher cipher = Cipher.getInstance(getTransformation());
        cipher.init(Cipher.DECRYPT_MODE, privKey);
        byte[] decoded = Base64.getDecoder().decode(cipherText);
        return new String(cipher.doFinal(decoded));
    }

    @Override
    public void saveKey(File file) throws Exception {
        if (keyPair == null) {
            throw new IllegalStateException("Aucune paire de clés à sauvegarder");
        }

        String content =
                "PUBLIC_KEY:\n" +
                        Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()) +
                        "\nPRIVATE_KEY:\n" +
                        Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());

        Files.writeString(file.toPath(), content);
    }

    @Override
    public void loadKey(File file) throws Exception {
        String content = Files.readString(file.toPath());
        String[] parts = content.split("\n");

        if (parts.length >= 4) {
            // Format complet avec clé publique et privée
            byte[] pub = Base64.getDecoder().decode(parts[1]);
            byte[] priv = Base64.getDecoder().decode(parts[3]);

            KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
            PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(pub));
            PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(priv));

            keyPair = new KeyPair(publicKey, privateKey);
            publicKeyOnly = null;
            privateKeyOnly = null;
        } else {
            throw new IllegalArgumentException("Format de fichier de clé invalide");
        }
    }

    // =====================
    // CHARGEMENT SÉPARÉ DES CLÉS
    // =====================

    public void loadPublicKey(File file) throws Exception {
        String content = Files.readString(file.toPath()).trim();
        byte[] decoded = Base64.getDecoder().decode(content);

        KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
        publicKeyOnly = kf.generatePublic(new X509EncodedKeySpec(decoded));
    }

    public void loadPrivateKey(File file) throws Exception {
        String content = Files.readString(file.toPath()).trim();
        byte[] decoded = Base64.getDecoder().decode(content);

        KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
        privateKeyOnly = kf.generatePrivate(new PKCS8EncodedKeySpec(decoded));
    }

    public void savePublicKey(File file) throws Exception {
        PublicKey pubKey = getPublicKey();
        if (pubKey == null) {
            throw new IllegalStateException("Aucune clé publique à sauvegarder");
        }
        Files.writeString(file.toPath(),
                Base64.getEncoder().encodeToString(pubKey.getEncoded()));
    }

    public void savePrivateKey(File file) throws Exception {
        PrivateKey privKey = getPrivateKey();
        if (privKey == null) {
            throw new IllegalStateException("Aucune clé privée à sauvegarder");
        }
        Files.writeString(file.toPath(),
                Base64.getEncoder().encodeToString(privKey.getEncoded()));
    }

    // =====================
    // GETTERS INTELLIGENTS
    // =====================

    private PublicKey getPublicKey() {
        if (keyPair != null) return keyPair.getPublic();
        return publicKeyOnly;
    }

    private PrivateKey getPrivateKey() {
        if (keyPair != null) return keyPair.getPrivate();
        return privateKeyOnly;
    }

    @Override
    public void saveText(String text, File file) throws Exception {
        Files.writeString(file.toPath(), text);
    }

    @Override
    public String loadText(File file) throws Exception {
        return Files.readString(file.toPath());
    }

    public String getPublicKeyAsBase64() {
        PublicKey pubKey = getPublicKey();
        if (pubKey == null) return "";
        return Base64.getEncoder().encodeToString(pubKey.getEncoded());
    }

    public String getPrivateKeyAsBase64() {
        PrivateKey privKey = getPrivateKey();
        if (privKey == null) return "";
        return Base64.getEncoder().encodeToString(privKey.getEncoded());
    }

    // =====================
    // SIGNATURE
    // =====================

    public byte[] sign(String message) throws Exception {
        PrivateKey privKey = getPrivateKey();
        if (privKey == null) {
            throw new IllegalStateException("Aucune clé privée pour signer");
        }

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privKey);
        signature.update(message.getBytes());

        return signature.sign();
    }

    public boolean verify(String message, byte[] signatureBytes) throws Exception {
        PublicKey pubKey = getPublicKey();
        if (pubKey == null) {
            throw new IllegalStateException("Aucune clé publique pour vérifier");
        }

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(pubKey);
        signature.update(message.getBytes());

        return signature.verify(signatureBytes);
    }

    public String signToBase64(String message) throws Exception {
        return Base64.getEncoder().encodeToString(sign(message));
    }

    public boolean verifyFromBase64(String message, String signatureBase64) throws Exception {
        byte[] sig = Base64.getDecoder().decode(signatureBase64);
        return verify(message, sig);
    }
}