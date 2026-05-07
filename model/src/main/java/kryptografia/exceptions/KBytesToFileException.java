/*
 * Projekt na Kryptografię (zad 1) - Szyfrowanie symetryczne "Triple ElGamala"
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

package kryptografia.exceptions;
///
/// @see kryptografia.exceptions.KException
///
public class KBytesToFileException extends KException {
    public KBytesToFileException(String message) {
        super(message);
    }
    public KBytesToFileException(String message, Throwable cause) {
        super(message, cause);
    }
}
