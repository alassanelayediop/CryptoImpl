package org.example.crypto;

import org.example.crypto.aes.CryptoAES;
import org.example.crypto.rsa.CryptoRSA;

public class CryptoFactory {

    public static Icrypto create(CryptoType type) {
        return switch (type) {
            case AES -> new CryptoAES();
            case RSA -> new CryptoRSA();
        };
    }
}
