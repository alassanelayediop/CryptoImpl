package org.example.crypto;

public enum KeySize {

    AES_128(CryptoType.AES, 128),
    AES_192(CryptoType.AES, 192),
    AES_256(CryptoType.AES, 256),

    RSA_1024(CryptoType.RSA, 1024),
    RSA_2048(CryptoType.RSA, 2048),
    RSA_4096(CryptoType.RSA, 4096);

    private final CryptoType type;
    private final int size;

    KeySize(CryptoType type, int size) {
        this.type = type;
        this.size = size;
    }

    public CryptoType getType() {
        return type;
    }

    public int getSize() {
        return size;
    }

    @Override
    public String toString() {
        return size + " bits";
    }
}
