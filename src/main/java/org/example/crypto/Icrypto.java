package org.example.crypto;

import java.io.File;

public interface Icrypto {
    void genKey(int keySize) throws Exception;
    String encrypt(String plainText) throws Exception;
    String decrypt(String cipherText) throws Exception;

    void saveKey(File file) throws Exception;
    void loadKey(File file) throws Exception;
    void saveText(String text, File file) throws Exception;
    String loadText(File file) throws Exception;

    // Méthodes pour gérer le mode de chiffrement
    void setMode(CryptoMode mode);
    CryptoMode getMode();
}