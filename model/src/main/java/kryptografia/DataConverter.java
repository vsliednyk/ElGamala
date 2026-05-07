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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import kryptografia.exceptions.*;


///
/// Klasa narzedziowa klasa statyczna
public class DataConverter {
    /// Konstruktor ktory zabezpiecza przed utworzeniem instancji tej klasy
    /// @throws UnsupportedOperationException
    private DataConverter() {
        throw new UnsupportedOperationException("To klasa przechowujaca narzedzia.");
    }

        public static byte[] fileToBytes(String filePath){
        try {
            return Files.readAllBytes(Paths.get(filePath));
        } catch (IOException e) {
            throw new KFileToBytesException("Nie udało się wczytać pliku: " + filePath, e);
        }
    }
    public static void bytesToFile(byte[] data, String filePath){
        try {
            Files.write(Paths.get(filePath), data);
        }
        catch (IOException e) {
            throw new KBytesToFileException("Nie udało się zapisu pliku: " + filePath, e);
        }
    }
    public static byte[] textToBytes(String text){
        try{
            return text.getBytes(StandardCharsets.UTF_8);
        }
        catch (NullPointerException e) {
            throw new KTextToBytesException("Nie udało się przekonwertować tekstu", e);
        }
    }
    public static String bytesToText(byte[] data){
        try{
            return new String(data, StandardCharsets.UTF_8);
        }
        catch(NullPointerException e) {
            throw new KBytesToTextException("Nie udało się dokonac konwersji na tekstu", e);
        }
    }
    public static String bytesToBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }
    public static byte[] base64ToBytes(String base64Text) {
        return Base64.getDecoder().decode(base64Text);
    }

    ///
    /// Funkcja pomocnicza: Pilnuje, aby bloki miały zawsze stałą długość (usuwa znak BigInteger)
    public static byte[] formatToExactLength(byte[] data, int targetLength) {
        byte[] result = new byte[targetLength];
        if (data.length == targetLength) {
            return data;
        } else if (data.length > targetLength) {
            System.arraycopy(data, data.length - targetLength, result, 0, targetLength);
        } else {
            System.arraycopy(data, 0, result, targetLength - data.length, data.length);
        }
        return result;
    }

    ///
    /// Funkcja pomocnicza: Dodaje dynamiczny padding PKCS7
    public static byte[] addPKCS7Padding(byte[] data, int blockSize){
        int paddingLength = blockSize - (data.length % blockSize);
        byte[] extendedData = new byte[data.length + paddingLength];

        System.arraycopy(data, 0, extendedData, 0, data.length);

        for (int i = 0; i < paddingLength; i++) {
            extendedData[data.length + i] = (byte) paddingLength;
        }
        return extendedData;
    }

    ///
    /// Funkcja pomocnicza: Usuwa dynamiczny padding PKCS7
    public static byte[] removePKCS7Padding(byte[] data){
        if (data == null || data.length == 0) {
            return data;
        }
        int paddingLength = data[data.length - 1];
        if (paddingLength > 0 && paddingLength <= data.length) {
            return Arrays.copyOfRange(data, 0, data.length - paddingLength);
        }
        return data;
    }





}