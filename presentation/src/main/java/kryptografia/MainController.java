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

import javafx.fxml.FXML;
import javafx.scene.control.*;
import java.io.File;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import javafx.stage.FileChooser;
import javafx.stage.Stage;




///
/// Glowna klasa obslugujaca UI
///
public class MainController {
    ///
    /// Kontrolki
    ///
    /// Klucze
    @FXML private TextField gField;
    @FXML private TextField hField;
    @FXML private TextField aField;
    @FXML private TextField modField;
    @FXML private Button generateKeysBtn;
    /// Pola kluczy
    @FXML private TextField loadKeyPathField;
    @FXML private Button loadKeyBtn;
    @FXML private TextField saveKeyPathField;
    @FXML private Button saveKeyBtn;
    /// Pola po lewej stronei (tekst)
    @FXML private TextField openPlainPathField;
    @FXML private Button openPlainBtn;
    @FXML private TextArea plainTextArea;
    @FXML private TextField savePlainPathField;
    @FXML private Button savePlainBtn;
    @FXML private Label plainStatusTitle;
    ///  Przyciski
    @FXML private Button encryptBtn;
    @FXML private Button decryptBtn;
    @FXML private ToggleGroup modeToggleGroup;
    @FXML private RadioButton fileModeRadio;
    @FXML private RadioButton windowModeRadio;
    /// Pola po prawej stronie (Szyfr)
    @FXML private TextField openCipherPathField;
    @FXML private Button openCipherBtn;
    @FXML private TextArea cipherTextArea;
    @FXML private TextField saveCipherPathField;
    @FXML private Button saveCipherBtn;
    @FXML private Label cipherStatusTitle;

    @FXML private Button resetButton;

    private final Map<String, String> filesPathsCache = new HashMap<>();
    private static final String KEY_PLAIN_IN = "PLAIN_IN";
    private static final String KEY_CIPHER_IN = "CIPHER_IN";
    private final SecureRandom random = new SecureRandom();

    ///
    /// Funkcja inicjujaca i przypisujaca eventy
    @FXML
    public void initialize() {
        // Podpiecie przyciskow glownych
        generateKeysBtn.setOnAction(event -> handleGenerateKeys());
        encryptBtn.setOnAction(event -> handleEncrypt());
        decryptBtn.setOnAction(event -> handleDecrypt());

        loadKeyBtn.setOnAction(event -> {
            File f = chooseFile("Wczytaj klucze", false);
            if(f != null) { loadKeyPathField.setText(f.getAbsolutePath()); handleReadKeysFromFile(); }
        });
        saveKeyBtn.setOnAction(event -> {
            File f = chooseFile("Zapisz klucze", true);
            if(f != null) { saveKeyPathField.setText(f.getAbsolutePath()); handleWriteKeysToFile(); }
        });

        // Podpiecie przyciskow plikow
        openPlainBtn.setOnAction(event -> handleOpenPlainFile());
        savePlainBtn.setOnAction(event -> handleSavePlainFile());
        openCipherBtn.setOnAction(event -> handleOpenCipherFile());
        saveCipherBtn.setOnAction(event -> handleSaveCipherFile());

        // Podpiecie eventow okien tekstu (zmiany)
        openPlainPathField.textProperty().addListener((obs, oldV, newV) -> handleWindowOpenPlainFileTextChanged());
        openCipherPathField.textProperty().addListener((obs, oldV, newV) -> handleWindowOpenCipherFileTextChanged());

        // Dodatkowe eventy dla TextArea zeby odswiezac status w trybie okna
        plainTextArea.textProperty().addListener((obs, oldV, newV) -> {
            if(windowModeRadio.isSelected()) setPlainStatus(newV.isEmpty() ? Status.WAITING_FOR_DATA : Status.TEXT_READY);
        });
        cipherTextArea.textProperty().addListener((obs, oldV, newV) -> {
            if(windowModeRadio.isSelected()) setCipherStatus(newV.isEmpty() ? Status.WAITING_FOR_DATA : Status.TEXT_READY);
        });

        // Przelacznik trybow
        modeToggleGroup.selectedToggleProperty().addListener((observable, oldValue, newValue) -> {
            boolean isFileMode = fileModeRadio.isSelected();
            plainTextArea.setEditable(!isFileMode);
            cipherTextArea.setEditable(!isFileMode);
            plainTextArea.setStyle(isFileMode ? "-fx-control-inner-background: #f4f4f4;" : "-fx-control-inner-background: #ffffff;");
            cipherTextArea.setStyle(isFileMode ? "-fx-control-inner-background: #f4f4f4;" : "-fx-control-inner-background: #ffffff;");
        });

        plainTextArea.setEditable(false);
        cipherTextArea.setEditable(false);
        plainTextArea.setStyle("-fx-control-inner-background: #f4f4f4;");
        cipherTextArea.setStyle("-fx-control-inner-background: #f4f4f4;");
        setPlainStatus(Status.WAITING_FOR_DATA);
        setCipherStatus(Status.WAITING_FOR_DATA);
        resetButton.setOnAction(event -> handleReset());
    }

    ///
    /// Funkcja generujaca losowe klucze matematyczne dla ElGamala
    ///
    /// Funkcja generujaca silne klucze matematyczne (Safe Primes)
    private void handleGenerateKeys(){
        int bitLength = 512;
        BigInteger p, q;

        // 1. Szukanie bezpiecznej liczby pierwszej p = 2q + 1
        // To może chwilę potrwać, bo q też musi być pierwsze
        do {
            q = BigInteger.probablePrime(bitLength - 1, random);
            p = q.multiply(BigInteger.valueOf(2)).add(BigInteger.ONE);
        } while (!MillerRabin.millerRabinTest(p,50)); // Sprawdzamy czy p jest pierwsze

        // Szukanie silnego generatora przy uzyciu force petli z 2 warunkami
        // g^2 != 1 (mod p) oraz g^q != 1 (mod p)
        BigInteger g = BigInteger.valueOf(2);
        while (true) {
            if (!g.modPow(BigInteger.valueOf(2), p).equals(BigInteger.ONE) &&
                    !g.modPow(q, p).equals(BigInteger.ONE)) {
                break; // Znaleźliśmy silny generator
            }
            g = g.add(BigInteger.ONE);
        }

        // 3. Losowanie klucza prywatnego a
        BigInteger pMinusOne = p.subtract(BigInteger.ONE);
        BigInteger a;
        do {
            a = new BigInteger(pMinusOne.bitLength(), random);
        } while (a.compareTo(BigInteger.ONE) <= 0 || a.compareTo(pMinusOne) >= 0);

        // 4. Wyliczenie klucza publicznego h = g^a mod p
        BigInteger h = g.modPow(a, p);

        // Ustawianie wartości w UI (Hex)
        modField.setText(p.toString(16));
        gField.setText(g.toString(16));
        aField.setText(a.toString(16));
        hField.setText(h.toString(16));

        setPlainStatus(Status.SUCCESS_GENERATED);
    }

    ///
    /// Funkcja czytajaca klucze z pliku txt na podstawie podanej sciezki
    private void handleReadKeysFromFile(){
        String path = loadKeyPathField.getText();
        if(path.isEmpty()){return;}
        try{
            String[] keysString = DataConverter.bytesToText(DataConverter.fileToBytes(path)).split("\n");
            if(keysString.length >= 4){
                gField.setText(keysString[0].trim());
                hField.setText(keysString[1].trim());
                aField.setText(keysString[2].trim());
                modField.setText(keysString[3].trim());
            }
        }catch(Exception e){
            setCipherStatus(Status.ERROR_KEY_MISSING);
            setPlainStatus(Status.ERROR_KEY_MISSING);
        }
    }

    ///
    /// Funkcja zapisujaca aktualnie wpisane klucze do pliku we wskazanej sciezce
    private void handleWriteKeysToFile(){
        String path = saveKeyPathField.getText();
        if(path.isEmpty()){return;}
        String keysString = gField.getText() + "\n" + hField.getText() + "\n" + aField.getText() + "\n" + modField.getText();
        try {
            DataConverter.bytesToFile(DataConverter.textToBytes(keysString), path);
        } catch (Exception e) {
            setPlainStatus(Status.ERROR_FILE_WRITE);
        }
    }

    ///
    /// Funkcja do obslugi przycisku wyboru pliku jawnego do zaszyfrowania
    /// @implNote Zapisuje sciezke w cache i laduje podglad tekstu jawnego
    private void handleOpenPlainFile(){
        File file = chooseFile("Wybierz plik wejsciowy do zaszyfrowania", false);
        if(file != null){
            openPlainPathField.setText(file.getAbsolutePath());
            filesPathsCache.put(KEY_PLAIN_IN, file.getAbsolutePath());

            try{
                plainTextArea.setText(DataConverter.bytesToText(DataConverter.fileToBytes(file.getAbsolutePath())));
                setPlainStatus(Status.FILE_READY);
            }catch(Exception e){
                setPlainStatus(Status.ERROR_FILE_READ);
            }
        }
    }

    ///
    /// Funkcja do obslugi przycisku zapisu pliku jawnego (po deszyfrowaniu)
    private void handleSavePlainFile(){
        File file = chooseFile("Wybierz gdzie zapisac plik odszyfrowany", true);
        if(file != null){
            savePlainPathField.setText(file.getAbsolutePath());
            try{
                DataConverter.bytesToFile(DataConverter.textToBytes(plainTextArea.getText()), file.getAbsolutePath());
            }
            catch(Exception e){
                setPlainStatus(Status.ERROR_FILE_WRITE);
            }
        }
    }

    ///
    /// Funkcja do obslugi przycisku wyboru pliku z szyfrogramem do odszyfrowania
    /// @implNote Zapisuje sciezke w cache i laduje podglad w formacie Base64
    /// @see DataConverter#bytesToBase64(byte[])
    private void handleOpenCipherFile(){
        File file = chooseFile("Wybierz plik wejsciowy do odszyfrowania", false);
        if(file != null){
            openCipherPathField.setText(file.getAbsolutePath());
            filesPathsCache.put(KEY_CIPHER_IN, file.getAbsolutePath());

            try{
                cipherTextArea.setText(DataConverter.bytesToBase64(DataConverter.fileToBytes(file.getAbsolutePath())));
                setCipherStatus(Status.FILE_READY);
            }catch(Exception e){
                setCipherStatus(Status.ERROR_FILE_READ);
            }
        }
    }

    ///
    /// Funkcja do obslugi przycisku zapisu szyfrogramu z Base64 do pliku
    /// @see DataConverter#base64ToBytes(String)
    private void handleSaveCipherFile(){
        File file = chooseFile("Wybierz gdzie zapisac plik zaszyfrowany", true);
        if(file != null){
            saveCipherPathField.setText(file.getAbsolutePath());
            try{
                DataConverter.bytesToFile(DataConverter.base64ToBytes(cipherTextArea.getText()), file.getAbsolutePath());
            }
            catch(Exception e){
                setCipherStatus(Status.ERROR_FILE_WRITE);
            }
        }
    }

    ///
    /// Funkcja pomocnicza tworzaca instancje silnika ElGamal do Szyfrowania
    /// @return {@link ElGamal} Zwraca gotowy obiekt szyfrujacy
    private ElGamal getElGamalCreateEncrypt() {
        String modText = modField.getText().trim();
        String gText = gField.getText().trim();
        String hText = hField.getText().trim();
        if (modText.isEmpty() || gText.isEmpty() || hText.isEmpty()) {
            throw new IllegalArgumentException("Brak kluczy publicznych!");
        }
        return new ElGamal(new BigInteger(gText, 16), new BigInteger(hText, 16), new BigInteger(modText, 16));
    }

    ///
    /// Funkcja pomocnicza tworzaca instancje silnika ElGamal do Deszyfrowania
    /// @return {@link ElGamal} Zwraca gotowy obiekt deszyfrujacy
    private ElGamal getElGamalCreateDecrypt() {
        String modText = modField.getText().trim();
        String aText = aField.getText().trim();
        if (modText.isEmpty() || aText.isEmpty()) {
            throw new IllegalArgumentException("Brak klucza prywatnego!");
        }
        return new ElGamal(new BigInteger(aText, 16), new BigInteger(modText, 16));
    }

    ///
    /// Glowna funkcja obslugujaca event szyfrowania danych
    private void handleEncrypt(){
        try {
            ElGamal engine = getElGamalCreateEncrypt();
            setPlainStatus(Status.PROCESSING);

            if (fileModeRadio.isSelected()) {
                String inPath = filesPathsCache.get(KEY_PLAIN_IN);
                if (inPath == null || inPath.isEmpty()) { setPlainStatus(Status.ERROR_FILE_MISSING); return; }

                String outPath = saveCipherPathField.getText();
                if (outPath.isEmpty()) {
                    handleSaveCipherFile();
                    outPath = saveCipherPathField.getText();
                    if (outPath.isEmpty()) return;
                }

                byte[] plainBytes = DataConverter.fileToBytes(inPath);
                byte[] cipherBytes = engine.encrypt(plainBytes);
                DataConverter.bytesToFile(cipherBytes, outPath);

                plainTextArea.setText(DataConverter.bytesToText(plainBytes));
                cipherTextArea.setText(DataConverter.bytesToBase64(cipherBytes));
            } else {
                String plainText = plainTextArea.getText();
                if (plainText.isEmpty()) { setPlainStatus(Status.WAITING_FOR_DATA); return; }

                byte[] cipherBytes = engine.encrypt(DataConverter.textToBytes(plainText));
                cipherTextArea.setText(DataConverter.bytesToBase64(cipherBytes));
            }

            setPlainStatus(Status.SUCCESS_ENCRYPTED);
            setCipherStatus(Status.SUCCESS_GENERATED);

        } catch (NumberFormatException e) {
            setPlainStatus(Status.ERROR_KEY_FORMAT);
        } catch (IllegalArgumentException e) {
            setPlainStatus(Status.ERROR_KEY_MISSING);
        } catch (Exception e) {
            setPlainStatus(Status.ERROR_UNKNOWN);
        }
    }

    ///
    /// Glowna funkcja obslugujaca event deszyfrowania danych
    private void handleDecrypt(){
        try {
            ElGamal engine = getElGamalCreateDecrypt();
            setCipherStatus(Status.PROCESSING);

            if (fileModeRadio.isSelected()) {
                String inPath = filesPathsCache.get(KEY_CIPHER_IN);
                if (inPath == null || inPath.isEmpty()) { setCipherStatus(Status.ERROR_FILE_MISSING); return; }

                String outPath = savePlainPathField.getText();
                if (outPath.isEmpty()) {
                    handleSavePlainFile();
                    outPath = savePlainPathField.getText();
                    if (outPath.isEmpty()) return;
                }

                byte[] cipherBytes = DataConverter.fileToBytes(inPath);
                byte[] plainBytes = engine.decrypt(cipherBytes);
                DataConverter.bytesToFile(plainBytes, outPath);

                cipherTextArea.setText(DataConverter.bytesToBase64(cipherBytes));
                plainTextArea.setText(DataConverter.bytesToText(plainBytes));
            } else {
                String cipherText = cipherTextArea.getText();
                if (cipherText.isEmpty()) { setCipherStatus(Status.WAITING_FOR_DATA); return; }

                byte[] plainBytes = engine.decrypt(DataConverter.base64ToBytes(cipherText));
                plainTextArea.setText(DataConverter.bytesToText(plainBytes));
            }

            setCipherStatus(Status.SUCCESS_DECRYPTED);
            setPlainStatus(Status.SUCCESS_GENERATED);

        } catch (NumberFormatException e) {
            setCipherStatus(Status.ERROR_KEY_FORMAT);
        } catch (IllegalArgumentException e) {
            setCipherStatus(Status.ERROR_KEY_MISSING);
        } catch (Exception e) {
            setCipherStatus(Status.ERROR_UNKNOWN);
        }
    }


    ///
    /// Funkcja aktualizujaca pamiec sciezki tekstu jawnego po jej wpisaniu
    private void handleWindowOpenPlainFileTextChanged(){
        filesPathsCache.put(KEY_PLAIN_IN, openPlainPathField.getText());
    }

    ///
    /// Funkcja aktualizujaca pamiec sciezki szyfrogramu po jej wpisaniu
    private void handleWindowOpenCipherFileTextChanged(){
        filesPathsCache.put(KEY_CIPHER_IN, openCipherPathField.getText());
    }

    ///
    /// Funkcja zmieniajaca powiadomienia i statusy panelu tekstu jawnego
    /// @param status Nowy zadany status z klasy Enum
    private void setPlainStatus(Status status) {
        plainStatusTitle.setText(status.getMessage());
        plainStatusTitle.setStyle(status.getStyle());
    }

    ///
    /// Funkcja zmieniajaca powiadomienia i statusy panelu szyfrogramu
    /// @param status Nowy zadany status z klasy Enum
    private void setCipherStatus(Status status) {
        cipherStatusTitle.setText(status.getMessage());
        cipherStatusTitle.setStyle(status.getStyle());
    }

    ///
    /// Funkcja pomocnicza otwierajaca systemowe menu wyboru pliku
    private File chooseFile(String title, boolean isSave){
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle(title);
        Stage stage = (Stage) gField.getScene().getWindow();
        return isSave ? fileChooser.showSaveDialog(stage) : fileChooser.showOpenDialog(stage);
    }

    ///
    /// Funkcja odpowiadajaca za twardy reset programu
    private void handleReset() {
        Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
        alert.setTitle("Potwierdzenie resetu");
        alert.setHeaderText("Czy na pewno chcesz zresetowac aplikacje?");
        alert.setContentText("Wszystkie wpisane dane, klucze, sciezki i wczytane pliki zostana wyczyszczone. Tej operacji nie mozna cofnac.");

        Stage stage = (Stage) gField.getScene().getWindow();
        alert.initOwner(stage);

        alert.showAndWait().ifPresent(response -> {
            if (response == ButtonType.OK) {
                gField.clear();
                hField.clear();
                aField.clear();
                modField.clear();
                loadKeyPathField.clear();
                saveKeyPathField.clear();

                openPlainPathField.clear();
                savePlainPathField.clear();
                plainTextArea.clear();

                openCipherPathField.clear();
                saveCipherPathField.clear();
                cipherTextArea.clear();

                filesPathsCache.clear();

                fileModeRadio.setSelected(true);

                setPlainStatus(Status.WAITING_FOR_DATA);
                setCipherStatus(Status.WAITING_FOR_DATA);
            }
        });
    }
}