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

public enum Status {

    // ==========================================
    // 1. STANY OCZEKIWANIA (Na bieżąco - Szare)
    // ==========================================
    WAITING_FOR_DATA("Oczekiwanie na dane...", "-fx-text-fill: gray;"),

    // ==========================================
    // 2. STANY GOTOWOŚCI (Na bieżąco - Niebieskie)
    // ==========================================
    TEXT_READY("Tekst wprowadzony (Gotowy)", "-fx-text-fill: #0078D7;"),
    FILE_READY("Plik zatwierdzony (Gotowy)", "-fx-text-fill: #0078D7;"),

    // ==========================================
    // 3. STANY PRZETWARZANIA (W trakcie - Pomarańczowe/Niebieskie)
    // ==========================================
    PROCESSING("Przetwarzanie danych...", "-fx-text-fill: orange;"),

    // ==========================================
    // 4. STANY SUKCESU (Po zakończeniu - Zielone)
    // ==========================================
    SUCCESS_ENCRYPTED("Zaszyfrowano pomyślnie!", "-fx-text-fill: green;"),
    SUCCESS_DECRYPTED("Odszyfrowano pomyślnie!", "-fx-text-fill: green;"),
    SUCCESS_GENERATED("Dane wygenerowane", "-fx-text-fill: green;"), // Dla połówki, która "odbiera" wynik

    // ==========================================
    // 5. STANY BŁĘDÓW (Z wyjątków - Czerwone)
    // ==========================================
    ERROR_KEY_MISSING("Błąd: Sprawdź klucze!", "-fx-text-fill: red;"),
    ERROR_KEY_FORMAT("Błąd: Klucz nie jest wartością Hex!", "-fx-text-fill: red;"), // Nowy błąd dla BigInteger
    ERROR_FILE_MISSING("Błąd: Brak pliku wejściowego!", "-fx-text-fill: red;"),
    ERROR_FILE_READ("Błąd odczytu pliku!", "-fx-text-fill: red;"),     // Złapie KFileToBytesException
    ERROR_FILE_WRITE("Błąd zapisu pliku!", "-fx-text-fill: red;"),     // Złapie KBytesToFileException
    ERROR_CONVERSION("Błąd konwersji danych!", "-fx-text-fill: red;"), // Złapie KTextToBytes/KBytesToText
    ERROR_UNKNOWN("Nieoczekiwany błąd!", "-fx-text-fill: red;");       // Złapie resztę KException

    private final String message;
    private final String style;

    Status(String message, String style) {
        this.message = message;
        this.style = style;
    }

    public String getMessage() { return message; }
    public String getStyle() { return style; }
}