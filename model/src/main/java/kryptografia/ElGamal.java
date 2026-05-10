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
/// @implNote To jest klasa implementacji algorytmu szyfrowania asymetrycznego ElGamala.
/// Algorytm opiera sie na trudnosci obliczania logarytmu dyskretnego w grupach skonczonych.
public class ElGamal {

    /** Generator grupy cyklicznej g */
    private BigInteger g;
    /** Klucz publiczny h (h = g^a mod modN) */
    private BigInteger h;
    /** Klucz prywatny a */
    private BigInteger a;
    /** Duza liczba pierwsza bedaca modulem operacji matematycznych */
    private BigInteger modN;

    /** Bezpieczny generator liczb losowych do wyznaczania wartosci efemerycznych k */
    private final SecureRandom random = new SecureRandom();

    ///
    /// Szyfrowanie (Konstruktor)
    /// @param g Generator grupy
    /// @param h Klucz publiczny odbiorcy
    /// @param modN Modul (liczba pierwsza)
    public ElGamal(BigInteger g, BigInteger h, BigInteger modN){
        this.g = g;
        this.h = h;
        this.modN = modN;
    }

    ///
    /// Deszyfrowanie (Konstruktor)
    /// @param a Klucz prywatny odbiorcy
    /// @param modN Modul (liczba pierwsza)
    public ElGamal(BigInteger a, BigInteger modN){
        this.a = a;
        this.modN = modN;
    }

    /// ⠀⠀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    /// ⠀⠀⣿⡟⠻⣿⡆⠀⠀⠀⠀⠀⠀⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣤⡖⠛⠿⠿⢿⣿⣶⣷⡀⠀⠀⠀⡀⠀⠀
    /// ⠀⠀⣿⡇⠀⣿⡇⠀⣴⣶⣶⣄⠀⣿⣿⣶⣶⡄⢀⣴⣶⣶⡄⠀⣶⣦⣶⡆⠀⠀⠀⠀⠀⣼⡘⠿⠃⠀⣀⣛⣂⡈⠈⣛⣛⣢⢔⠨⠤⠀⠀
    /// ⠀⠀⣿⣷⣾⣿⠁⢸⣿⡇⢸⣿⠀⣿⣿⠈⣿⡇⢸⣿⠀⢹⣿⠀⣿⡟⠁⠀⠀⠀⠀⢀⣾⡿⡪⣂⢍⡀⡂⢌⣻⣻⠆⠈⡛⢁⠿⢓⡀⠠⠁
    /// ⠀⠀⣿⡇⠈⣿⣧⢸⣿⡇⢸⣿⠀⣿⣿⠀⣿⡇⢸⣿⠿⠿⠿⠀⣿⡇⠀⠀⠀⢀⣴⣿⢟⠍⠮⣿⢿⣮⡾⣢⣷⣛⣉⡡⠜⠁⠱⡅⠀⠀⠀
    /// ⠀⠀⣿⣇⣠⣿⡟⢸⣿⡇⢸⣿⠀⣿⣿⢀⣿⡇⢸⣿⡀⣸⣿⠀⣿⡇⠀⠀⣰⣿⢏⡒⣡⢢⢡⠐⠯⢛⠿⢻⠿⡻⣹⡇⠀⠀⠀⢡⠀⠀⠀
    /// ⠀⠀⠿⠿⠿⠛⠁⠀⠻⠿⠿⠋⠀⠿⠿⠿⠿⠃⠈⠻⠿⠿⠃⠀⠿⠇⠀⣰⣿⡿⢃⠀⣿⣿⣿⣴⡼⣸⣸⠀⢆⢰⣷⣿⠀⠀⠀⠀⠀⠀⠀
    /// ⢀⣀⡀⠀⣄⡠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣵⣆⡁⠣⠻⣻⣿⣷⣷⣟⣮⣿⣿⣿⣇⠀⠀⠀⠀⠀⠀
    /// ⢸⣿⡇⣰⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠿⠿⠿⠿⠿⠿⣾⣶⣌⠙⡙⡝⡿⠿⠿⣿⣎⣊⣿⠤⠤⠀⠀⠀
    /// ⢸⣿⣧⣿⡇⠀⠀⣶⡆⢰⣶⠀⢰⣶⣴⣶⣶⣆⠀⣶⡀⢰⣶⠀⣴⣶⣶⣆⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀
    /// ⢸⣿⣿⣿⣇⠀⠀⣿⡇⢸⣿⠀⢸⣿⠋⠀⢸⣿⢰⣿⡇⣿⡇⠐⠛⠃⣸⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    /// ⢸⣿⡏⢹⣿⡀⠀⣿⡇⢸⣿⠀⢸⣿⠀⠀⠸⣿⣸⣿⣧⣿⠇⠀⣴⡾⢻⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    /// ⢸⣿⡇⠘⣿⣇⠀⣿⡇⢸⣿⠀⢸⣿⠀⠀⠀⣿⣿⠁⣿⣿⠀⢸⣿⡁⣸⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    /// ⠸⠿⠇⠀⠻⠿⠀⠻⠿⠻⠿⠄⠸⠿⠀⠀⠀⠹⠿⠀⠻⠿⠀⠈⠿⠿⠻⠿⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    /// Glowna funkcja do szyfrowania danych binarnych.
    /// @param data Tablica bajtow tekstu jawnego.
    /// @return Zaszyfrowana tablica bajtow (szyfrogram o podwojnej dlugosci wzgledem blokow).
    public byte[] encrypt(byte[] data) {
        // Wyznaczanie rozmiaru bloku na podstawie dlugosci modulu w bajtach
        int keyByteLength = (modN.bitLength() + 7) / 8;

        // Rozmiar bloku tekstu jawnego musi byc o 1 bajt mniejszy od modulu (warunek m < N)
        int plainBlockSize = keyByteLength - 1;

        // Uzupelnienie danych wejsciowych zgodnie ze standardem PKCS7
        byte[] paddedData = DataConverter.addPKCS7Padding(data, plainBlockSize);

        // Sumaryczna liczba blokow do przetworzenia
        int totalBlocks = paddedData.length / plainBlockSize;

        // Alokacja przestrzeni: kazdy blok generuje pare (c1, c2), gdzie kazdy ma keyByteLength
        byte[] cipherData = new byte[totalBlocks * keyByteLength * 2];

        // Iteracyjne szyfrowanie blokow
        for (int i = 0; i < totalBlocks; i++) {
            byte[] blockBytes = new byte[plainBlockSize];
            System.arraycopy(paddedData, i * plainBlockSize, blockBytes, 0, plainBlockSize);

            // Konwersja bloku bajtow na liczbe dodatnia (BigInteger)
            BigInteger m = new BigInteger(1, blockBytes);
            BigInteger[] encrypted = encryptBlock(m);

            // Formatowanie BigInteger z powrotem na bajty o stalej dlugosci
            byte[] c1Bytes = DataConverter.formatToExactLength(encrypted[0].toByteArray(), keyByteLength);
            byte[] c2Bytes = DataConverter.formatToExactLength(encrypted[1].toByteArray(), keyByteLength);

            // Skladanie szyfrogramu: [c1][c2]...
            System.arraycopy(c1Bytes, 0, cipherData, i * (keyByteLength * 2), keyByteLength);
            System.arraycopy(c2Bytes, 0, cipherData, i * (keyByteLength * 2) + keyByteLength, keyByteLength);
        }
        return cipherData;
    }

    /// Glowna funkcja do deszyfrowania danych binarnych.
    /// @param cipherData Tablica bajtow szyfrogramu.
    /// @return Odszyfrowana tablica bajtow po usunieciu dopelnienia.
    /// @throws IllegalArgumentException Jesli dlugosc szyfrogramu jest niezgodna z rozmiarem klucza.
    public byte[] decrypt(byte[] cipherData) {
        int keyByteLength = (modN.bitLength() + 7) / 8;
        int cipherBlockSize = keyByteLength * 2;
        int plainBlockSize = keyByteLength - 1;

        if (cipherData.length % cipherBlockSize != 0) {
            throw new IllegalArgumentException("Uszkodzony szyfrogram (nieprawidlowa dlugosc)!");
        }

        int totalBlocks = cipherData.length / cipherBlockSize;
        byte[] plainData = new byte[totalBlocks * plainBlockSize];

        for (int i = 0; i < totalBlocks; i++) {
            byte[] c1Bytes = new byte[keyByteLength];
            byte[] c2Bytes = new byte[keyByteLength];

            // Wyodrebnienie pary (c1, c2) z biezacego bloku szyfrogramu
            System.arraycopy(cipherData, i * cipherBlockSize, c1Bytes, 0, keyByteLength);
            System.arraycopy(cipherData, i * cipherBlockSize + keyByteLength, c2Bytes, 0, keyByteLength);

            BigInteger c1 = new BigInteger(1, c1Bytes);
            BigInteger c2 = new BigInteger(1, c2Bytes);

            // Matematyczne wyznaczenie tekstu jawnego m
            BigInteger m = decryptBlock(c1, c2);

            // Formatowanie wyniku m do oryginalnego rozmiaru bloku
            byte[] mBytes = DataConverter.formatToExactLength(m.toByteArray(), plainBlockSize);
            System.arraycopy(mBytes, 0, plainData, i * plainBlockSize, plainBlockSize);
        }

        // Usuniecie bajtow dopelnienia PKCS7
        return DataConverter.removePKCS7Padding(plainData);
    }

    ///
    /// Podstawowa funkcja szyfrowania pojedynczego bloku danych.
    /// Wykorzystuje losowa wartosc k (efemeryczna) dla kazdego bloku.
    /// @param m Wiadomosc jako BigInteger.
    /// @return Tablica BigInteger zawierajaca pare {c1, c2}.
    private BigInteger[] encryptBlock(BigInteger m){
        if(m.compareTo(modN) >= 0){
            throw new IllegalArgumentException("Wiadomosc musi byc mniejsza od N");
        }
        BigInteger modNMinusOne = modN.subtract(BigInteger.ONE);
        BigInteger k;

        // Losowanie k ∈ [2, modN-2]
        do{
            k = new BigInteger(modNMinusOne.bitLength(), random);
        } while(k.compareTo(BigInteger.ONE) <= 0 || k.compareTo(modNMinusOne) >= 0);

        // c1 = g^k mod N
        BigInteger c1 = g.modPow(k, modN);
        // c2 = m * h^k mod N
        BigInteger hToPowk = h.modPow(k, modN);
        BigInteger c2 = m.multiply(hToPowk).mod(modN);

        return new BigInteger[]{c1, c2};
    }

    ///
    /// Podstawowa funkcja deszyfrowania pojedynczego bloku danych.
    /// Wykorzystuje klucz prywatny a do odzyskania m.
    /// @param c1 Pierwsza czesc szyfrogramu.
    /// @param c2 Druga czesc szyfrogramu.
    /// @return Odszyfrowana wiadomosc jako BigInteger.
    private BigInteger decryptBlock(BigInteger c1, BigInteger c2) {
        // s = c1^a mod N
        BigInteger s = c1.modPow(a, modN);
        // m = c2 * s^-1 mod N
        BigInteger sInverse = s.modInverse(modN);
        BigInteger m = c2.multiply(sInverse).mod(modN);

        return m;
    }
}