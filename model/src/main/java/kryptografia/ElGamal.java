/*
 * Projekt na Kryptografię (zad 2) - Szyfrowanie asymetryczne "ElGamala"
 * Copyright (C) 2026 Igor Wiktorowicz & Viktor Sliednyk
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
package kryptografia;

import java.math.BigInteger;
import java.security.SecureRandom;

///
/// @implNote To jest klasa implementacji algorytmu szyfrowania asymetrycznego ElGamala
public class ElGamal {

    private BigInteger g; // Generator
    private BigInteger h; // Public Key
    private BigInteger a; // Private Key
    private BigInteger modN; // Primary number

    private final SecureRandom random = new SecureRandom(); // Safe version of Math.random()

    ///
    /// Szyfrowanie
    public ElGamal(BigInteger g, BigInteger h, BigInteger modN){
        this.g = g;
        this.h = h;
        this.modN = modN;
    }

    ///
    /// Deszyfrowanie
    ///
    public ElGamal(BigInteger a, BigInteger modN){
        this.a = a;
        this.modN = modN;
    }

    /// Główna funkcja do szyfrowania pliku/tekstu
    public byte[] encrypt(byte[] data) {
        int keyByteLength = (modN.bitLength() + 7) / 8;
        int plainBlockSize = keyByteLength - 1;

        // Użycie funkcji z klasy DataConverter
        byte[] paddedData = DataConverter.addPKCS7Padding(data, plainBlockSize);
        int totalBlocks = paddedData.length / plainBlockSize;

        byte[] cipherData = new byte[totalBlocks * keyByteLength * 2];

        for (int i = 0; i < totalBlocks; i++) {
            byte[] blockBytes = new byte[plainBlockSize];
            System.arraycopy(paddedData, i * plainBlockSize, blockBytes, 0, plainBlockSize);

            BigInteger m = new BigInteger(1, blockBytes);
            BigInteger[] encrypted = encryptBlock(m);

            byte[] c1Bytes = DataConverter.formatToExactLength(encrypted[0].toByteArray(), keyByteLength);
            byte[] c2Bytes = DataConverter.formatToExactLength(encrypted[1].toByteArray(), keyByteLength);

            System.arraycopy(c1Bytes, 0, cipherData, i * (keyByteLength * 2), keyByteLength);
            System.arraycopy(c2Bytes, 0, cipherData, i * (keyByteLength * 2) + keyByteLength, keyByteLength);
        }
        return cipherData;
    }

    /// Główna funkcja do deszyfrowania pliku/tekstu
    public byte[] decrypt(byte[] cipherData) {
        int keyByteLength = (modN.bitLength() + 7) / 8;
        int cipherBlockSize = keyByteLength * 2;
        int plainBlockSize = keyByteLength - 1;

        if (cipherData.length % cipherBlockSize != 0) {
            throw new IllegalArgumentException("Uszkodzony szyfrogram (nieprawidłowa długość)!");
        }

        int totalBlocks = cipherData.length / cipherBlockSize;
        byte[] plainData = new byte[totalBlocks * plainBlockSize];

        for (int i = 0; i < totalBlocks; i++) {
            byte[] c1Bytes = new byte[keyByteLength];
            byte[] c2Bytes = new byte[keyByteLength];

            System.arraycopy(cipherData, i * cipherBlockSize, c1Bytes, 0, keyByteLength);
            System.arraycopy(cipherData, i * cipherBlockSize + keyByteLength, c2Bytes, 0, keyByteLength);

            BigInteger c1 = new BigInteger(1, c1Bytes);
            BigInteger c2 = new BigInteger(1, c2Bytes);

            BigInteger m = decryptBlock(c1, c2);

            byte[] mBytes = DataConverter.formatToExactLength(m.toByteArray(), plainBlockSize);
            System.arraycopy(mBytes, 0, plainData, i * plainBlockSize, plainBlockSize);
        }

        return DataConverter.removePKCS7Padding(plainData);
    }

    private BigInteger[] encryptBlock(BigInteger m){
        if(m.compareTo(modN) >= 0){
            throw new IllegalArgumentException("Wiadomosc musi byc mniejsza od N");
        }
        BigInteger modNMinusOne = modN.subtract(BigInteger.ONE);
        BigInteger k;

        do{
            k = new BigInteger(modNMinusOne.bitLength(), random);
        } while(k.compareTo(BigInteger.ONE) <= 0 || k.compareTo(modNMinusOne) >= 0);

        BigInteger c1 = g.modPow(k, modN);
        BigInteger hToPowk = h.modPow(k, modN);

        BigInteger c2 = m.multiply(hToPowk).mod(modN);

        return new BigInteger[]{c1, c2};
    }

    private BigInteger decryptBlock(BigInteger c1, BigInteger c2) {
        BigInteger s = c1.modPow(a, modN);
        BigInteger sInverse = s.modInverse(modN);
        BigInteger m = c2.multiply(sInverse).mod(modN);

        return m;
    }
}