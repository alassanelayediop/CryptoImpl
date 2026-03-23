package org.example.crypto.dh;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class DiffieHellmanService {

    private KeyPair keyPair;
    private PublicKey otherPublicKey;
    private byte[] sharedSecret;

    /**
     * Génère une paire de clés Diffie-Hellman
     * @param keySize Taille de la clé (1024, 2048, 3072)
     */
    public void generateKeys(int keySize) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
        kpg.initialize(keySize);
        keyPair = kpg.generateKeyPair();
        sharedSecret = null;
        otherPublicKey = null;
    }

    /**
     * Calcule le secret partagé à partir de la clé publique de l'autre partie
     * @param otherPublicKeyBase64 La clé publique de l'autre partie en Base64
     */
    public void computeSharedSecret(String otherPublicKeyBase64) throws Exception {
        if (keyPair == null) {
            throw new IllegalStateException("Générez d'abord votre paire de clés");
        }

        byte[] otherPubKeyBytes = Base64.getDecoder().decode(otherPublicKeyBase64);
        KeyFactory kf = KeyFactory.getInstance("DH");
        otherPublicKey = kf.generatePublic(new X509EncodedKeySpec(otherPubKeyBytes));

        KeyAgreement ka = KeyAgreement.getInstance("DH");
        ka.init(keyPair.getPrivate());
        ka.doPhase(otherPublicKey, true);
        sharedSecret = ka.generateSecret();
    }

    /**
     * Obtient la clé publique locale en Base64
     */
    public String getPublicKeyAsBase64() {
        if (keyPair == null) return "";
        return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    }

    /**
     * Obtient le secret partagé en hexadécimal
     */
    public String getSharedSecretAsHex() {
        if (sharedSecret == null) return "";
        return bytesToHex(sharedSecret);
    }

    /**
     * Dérive une clé AES à partir du secret partagé
     * @param keySize Taille de la clé AES (128, 192, 256)
     */
    public String deriveAESKey(int keySize) throws Exception {
        if (sharedSecret == null) {
            throw new IllegalStateException("Calculez d'abord le secret partagé");
        }

        // Hacher le secret partagé pour obtenir une clé de la bonne taille
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha.digest(sharedSecret);

        // Tronquer ou utiliser selon la taille demandée
        int keyBytes = keySize / 8;
        byte[] keyData = new byte[keyBytes];
        System.arraycopy(hash, 0, keyData, 0, Math.min(keyBytes, hash.length));

        SecretKey aesKey = new SecretKeySpec(keyData, "AES");
        return Base64.getEncoder().encodeToString(aesKey.getEncoded());
    }

    /**
     * Sauvegarde la clé publique dans un fichier
     */
    public void savePublicKey(File file) throws Exception {
        if (keyPair == null) {
            throw new IllegalStateException("Aucune clé publique à sauvegarder");
        }
        Files.writeString(file.toPath(), getPublicKeyAsBase64());
    }

    /**
     * Charge la clé publique de l'autre partie depuis un fichier
     */
    public void loadOtherPublicKey(File file) throws Exception {
        String content = Files.readString(file.toPath()).trim();
        computeSharedSecret(content);
    }

    /**
     * Convertit des bytes en hexadécimal
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Obtient les informations sur le secret partagé
     */
    public String getSharedSecretInfo() {
        if (sharedSecret == null) return "Aucun secret partagé calculé";
        return String.format("Taille: %d bits (%d bytes)", sharedSecret.length * 8, sharedSecret.length);
    }
}