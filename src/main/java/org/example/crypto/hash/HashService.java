package org.example.crypto.hash;

import org.example.crypto.HashAlgorithm;

import java.io.File;
import java.nio.file.Files;
import java.security.MessageDigest;

public class HashService {

    /**
     * Hache un texte avec l'algorithme spécifié
     * @param text Le texte à hacher
     * @param algorithm L'algorithme de hachage
     * @return Le hash en hexadécimal
     */
    public static String hashText(String text, HashAlgorithm algorithm) throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm.getAlgorithm());
        byte[] hash = md.digest(text.getBytes());
        return bytesToHex(hash);
    }

    /**
     * Hache un fichier avec l'algorithme spécifié
     * @param file Le fichier à hacher
     * @param algorithm L'algorithme de hachage
     * @return Le hash en hexadécimal
     */
    public static String hashFile(File file, HashAlgorithm algorithm) throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm.getAlgorithm());
        byte[] fileBytes = Files.readAllBytes(file.toPath());
        byte[] hash = md.digest(fileBytes);
        return bytesToHex(hash);
    }

    /**
     * Vérifie si un hash correspond à un texte
     * @param text Le texte original
     * @param expectedHash Le hash attendu (hexadécimal)
     * @param algorithm L'algorithme utilisé
     * @return true si le hash correspond
     */
    public static boolean verifyHash(String text, String expectedHash, HashAlgorithm algorithm) throws Exception {
        String computedHash = hashText(text, algorithm);
        return computedHash.equalsIgnoreCase(expectedHash.trim());
    }

    /**
     * Convertit un tableau de bytes en chaîne hexadécimale
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Obtient la taille du hash en bits pour un algorithme donné
     */
    public static int getHashSize(HashAlgorithm algorithm) {
        return switch (algorithm) {
            case MD5 -> 128;
            case SHA1 -> 160;
            case SHA256 -> 256;
            case SHA512 -> 512;
        };
    }
}