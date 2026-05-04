/*
 * Projekt na Kryptografię (zad 1) - Szyfrowanie symetryczne "Triple DES"
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
import kryptografia.exceptions.DES.KDNoSHAAlgorythmException;

///
/// Klasa narzedziowa klasa statyczna
public class DataConverter {
    /// Konstruktor ktory zabezpiecza przed utworzeniem instancji tej klasy
    /// @throws UnsupportedOperationException
    private DataConverter() {
        throw new UnsupportedOperationException("To klasa przechowujaca narzedzia.");
    }
///
/// Funkcja konwertujaca plik na bajty
/// @param filePath Sciezka do pliku
/// @return {@code byte[]}
/// @throws KFileToBytesException
    public static byte[] fileToBytes(String filePath){
        try {
            return Files.readAllBytes(Paths.get(filePath));
        } catch (IOException e) {
            throw new KFileToBytesException("Nie udało się wczytać pliku: " + filePath, e);
        }
    }
///
/// Funkcja konwertujaca bajty na plik
/// @param data bajty do kowersji
/// @param filePath sciezka do pliku
/// @throws KBytesToFileException
    public static void bytesToFile(byte[] data, String filePath){
        try {
            Files.write(Paths.get(filePath), data);
        }
        catch (IOException e) {
            throw new KBytesToFileException("Nie udało się zapisu pliku: " + filePath, e);
        }
    }
    ///
    /// Funkcja konwertujaca tekst na bajty przy
    /// @implNote Uzywa charset UTF8
    /// @param text tekst do konwersji
    /// @return {@code byte[]}
    /// @throws KTextToBytesException
    public static byte[] textToBytes(String text){
        try{
            return text.getBytes(StandardCharsets.UTF_8);
        }
        catch (NullPointerException e) {
            throw new KTextToBytesException("Nie udało się przekonwertować tekstu", e);
        }
    }
///
/// Funkcja zamieniajaca bajty w tekst
/// @param data bajty do przerobienia
/// @return {@code String}
/// @throws KBytesToTextException
    public static String bytesToText(byte[] data){
        try{
            return new String(data, StandardCharsets.UTF_8);
        }
        catch(NullPointerException e) {
            throw new KBytesToTextException("Nie udało się dokonac konwersji na tekstu", e);
        }
    }
///
/// Funkcja do przekonwertowania tablicy bajtow na tekst o kodowaniu Base64
/// @param data tablica bajtow do zakodowania
/// @return 
    public static String bytesToBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }
    ///
    /// Funkcja do przekonwertowania tesktu o kodowaniu Base64 na tablice bajtow
    /// @param base64Text Tekst o kodowaniu Base64
    /// @return {@code byte[]}
    public static byte[] base64ToBytes(String base64Text) {
        return Base64.getDecoder().decode(base64Text);
    }

///
/// Funkcja pomagajaca rozszerzyc podana tablice bajtow do bloku o rozmiarze 8
/// @param data tablcia bajtow ktora trzeba rozszerzyc
/// @return {@code byte[]}
    public static byte[] addPKCS7DESPadding(byte[] data){
        int blockSize = 8; // DES wymaga rozmiaz 64 bity -> 8 bajtów
        int paddingLength = blockSize - (data.length % blockSize);
        byte[] extendedData = new byte[data.length + paddingLength];


        System.arraycopy(data, 0, extendedData, 0, data.length); // From | F:Exact pos | To | T:Exact pos | amount to copy

        for (int i = 0; i < paddingLength; i++) {
            extendedData[data.length + i] = (byte) paddingLength;
        }
        return extendedData;
    }
///
/// Funkcja usuwajaca zbedne bajty po rozszerzeniu do bloku o rozmiarze 8
/// @param data tablica bajtow do zmniejszenia
/// @return {@code byte[]}
    public static byte[] removePKCS7DESPadding(byte[] data){
        if (data == null || data.length == 0) {
            return data;
        }

        int paddingLength = data[data.length - 1];

        if (paddingLength > 0 && paddingLength <= 8) {
            return Arrays.copyOfRange(data, 0, data.length - paddingLength);
        }
        return data;
    }

    /// Funkcja pozwalajaca na uzycie dowolnego hasla
    /// @param pass dowolny tekst podany jako haslo
    /// @return {@code byte[]} Zwraca tablice bajtow
    /// @throws KDNoSHAAlgorythmException
    ///
    private static byte[] sha256(String pass){
        try {
            return MessageDigest.getInstance("SHA-256").digest(pass.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new KDNoSHAAlgorythmException("No SHA-256 algorithm found.", e);
        }
    }
    /// Funkcja do obcinania bajtow
    /// @implNote Korzysta z {@link #sha256(String)}
    /// @param key dowolny tekst
    /// @return
    public static byte[] extract8KeyBytes (String key){
        try{
            byte[] wynik = new byte[8];
            System.arraycopy(DataConverter.sha256(key),0,wynik,0,8);
            return wynik;
        }
        catch(KDNoSHAAlgorythmException e){
            throw new KException("SHA-256 algorithm not found.", e);
        }
    }

}
