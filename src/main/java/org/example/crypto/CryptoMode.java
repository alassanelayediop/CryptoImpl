package org.example.crypto;

public enum CryptoMode {
    ECB("ECB"),
    CBC("CBC");

    private final String mode;

    CryptoMode(String mode) {
        this.mode = mode;
    }

    public String getMode() {
        return mode;
    }

    @Override
    public String toString() {
        return mode;
    }
}