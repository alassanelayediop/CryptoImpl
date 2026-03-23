package org.example.logic;

import org.example.crypto.CryptoType;
import org.example.crypto.Icrypto;

public class CryptoService {

    private Icrypto crypto;

    public void init(CryptoType type, int keySize) throws Exception {
        switch (type) {
            case AES -> crypto = new org.example.crypto.aes.CryptoAES();
            case RSA -> crypto = new org.example.crypto.rsa.CryptoRSA();
        }
        crypto.genKey(keySize);
    }

    public String encrypt(String text) throws Exception {
        return crypto.encrypt(text);
    }

    public String decrypt(String text) throws Exception {
        return crypto.decrypt(text);
    }

    public void saveKey(java.io.File f) throws Exception {
        crypto.saveKey(f);
    }

    public void loadKey(java.io.File f) throws Exception {
        crypto.loadKey(f);
    }
}


//package org.example.logic;
//
//import org.example.crypto.*;
//
//public class CryptoService {
//
//    private Icrypto crypto;
//    private Object key;
//
//    public void init(CryptoType type, int keySize) throws Exception {
//        crypto = CryptoFactory.create(type);
//        key = crypto.genKey(keySize);
//    }
//
//    public String encrypt(String text) throws Exception {
//        return crypto.encrypt(key, text);
//    }
//
//    public String decrypt(String text) throws Exception {
//        return crypto.decrypt(key, text);
//    }
//
//    public Object getKey() {
//        return key;
//    }
//}
