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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import java.math.BigInteger;
import java.security.SecureRandom;
import static org.junit.jupiter.api.Assertions.*;

///
/// @implNote Klasa testowa sprawdzajaca matematyczna poprawnosc implementacji ElGamala
class ElGamalTest {

    private final SecureRandom random = new SecureRandom();



    @Test
    @DisplayName("Test poprawnosci: 100 rund z pelna generacja silnych kluczy")
    void testFullElGamalCycle() {
        for (int i = 1; i <= 100; i++) {
            //  Szukanie bezpiecznej liczby pierwszej p = 2q + 1
            BigInteger q, p;
            int bitLength = 256; // Dla szybszych testow 256 bitow, w UI masz 512+
            do {
                q = BigInteger.probablePrime(bitLength - 1, random);
                p = q.multiply(BigInteger.valueOf(2)).add(BigInteger.ONE);
            } while (!MillerRabin.millerRabinTest(p,40));

            //  Szukanie silnego generatora g (nieuproszczonego)
            BigInteger g = BigInteger.valueOf(2);
            while (true) {
                if (!g.modPow(BigInteger.valueOf(2), p).equals(BigInteger.ONE) &&
                        !g.modPow(q, p).equals(BigInteger.ONE)) {
                    break;
                }
                g = g.add(BigInteger.ONE);
            }

            //  Klucze
            BigInteger a = new BigInteger(p.bitLength() - 1, random).mod(p.subtract(BigInteger.ONE)).add(BigInteger.ONE);
            BigInteger h = g.modPow(a, p);

            //  Inicjalizacja silnikow
            ElGamal encryptor = new ElGamal(g, h, p);
            ElGamal decryptor = new ElGamal(a, p);

            //  Dane testowe (losowa dlugosc i zawartosc)
            byte[] originalData = new byte[random.nextInt(300) + 1];
            random.nextBytes(originalData);

            //  Test krypto
            byte[] cipher = encryptor.encrypt(originalData);
            byte[] decrypted = decryptor.decrypt(cipher);

            // Asercja - sprawdzenie czy odzyskalismy to samo
            assertArrayEquals(originalData, decrypted, "Blad w rundzie numer: " + i);
        }
    }

    @Test
    @DisplayName("Test Millera-Rabina na znanych liczbach")
    void millerRabinKnownValues() {
        // Znane liczby pierwsze
        assertTrue(MillerRabin.millerRabinTest(BigInteger.valueOf(7919), 40));
        assertTrue(MillerRabin.millerRabinTest(new BigInteger("170141183460469231731687303715884105727"), 40)); // Mersenne prime

        // Znane liczby zlozone
        assertFalse(MillerRabin.millerRabinTest(BigInteger.valueOf(7920), 40));
        assertFalse(MillerRabin.millerRabinTest(BigInteger.valueOf(221), 40)); // 13 * 17
    }
}