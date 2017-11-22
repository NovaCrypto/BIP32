/*
 *  BIP32 library, a Java implementation of BIP32
 *  Copyright (C) 2017 Alan Evans, NovaCrypto
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 *  Original source: https://github.com/NovaCrypto/BIP32
 *  You can contact the authors via github issues.
 */

package io.github.novacrypto;

import static io.github.novacrypto.Hex.toHex;
import static io.github.novacrypto.base58.Base58.base58Decode;
import static org.junit.Assert.assertEquals;

public final class Asserts {

    /**
     * Compares two base58 keys. On failure, shows hex comparison.
     *
     * @param expectedKey Base58 string of expected key
     * @param actualKey   Base58 string of actual key
     */
    public static void assertBase58KeysEqual(final String expectedKey, final String actualKey) {
        String failureMessage = "";
        if (!expectedKey.equals(actualKey)) {
            final String expectedDecoded = decodeKey(expectedKey);
            final String actualDecoded = decodeKey(actualKey);
            final int index = indexOfFirstDifference(expectedDecoded, actualDecoded);
            final String differencePointer = String.format("%1$" + (index + 1) + "s", "^");
            failureMessage = String.format("\n" +
                            "          version  d  f.print   child    chain code                                                       key                                                               checksum\n" +
                            "Expected :%s\n" +
                            "Actual   :%s\n" +
                            "          %s",
                    expectedDecoded, actualDecoded, differencePointer);
        }
        assertEquals(failureMessage, expectedKey, actualKey);
    }

    static void assertBase58AddressEqual(final String expectedAddress, final String actualAddress) {
        String failureMessage = "";
        if (!expectedAddress.equals(actualAddress)) {
            final String expectedDecoded = decodeAddress(expectedAddress);
            final String actualDecoded = decodeAddress(actualAddress);
            final int index = indexOfFirstDifference(expectedDecoded, actualDecoded);
            final String differencePointer = String.format("%1$" + (index + 1) + "s", "^");
            failureMessage = String.format("\n" +
                            "       version                  key                   checksum\n" +
                            "Expected :%s\n" +
                            "Actual   :%s\n" +
                            "          %s",
                    expectedDecoded, actualDecoded, differencePointer);
        }
        assertEquals(failureMessage, expectedAddress, actualAddress);
    }

    private static int indexOfFirstDifference(final String a, final String b) {
        final int length = Math.min(a.length(), b.length());
        for (int i = 0; i < length; i++) {
            if (a.charAt(i) != b.charAt(i)) return i;
        }
        return length;
    }

    private static String decodeKey(final String key) {
        final String s = toHex(base58Decode(key));
        return breakString(s, 82, new int[]{4, 1, 4, 4, 32, 33, 4});
    }

    private static String decodeAddress(final String address) {
        final String s = toHex(base58Decode(address));
        return breakString(s, 25, new int[]{1, 20, 4});
    }

    private static String breakString(final String s, final int expectedLength, final int[] indexes) {
        assertEquals(expectedLength * 2, s.length());
        StringBuilder sb = new StringBuilder();
        int last = 0;
        for (int index : indexes) {
            final int current = last + index * 2;
            sb.append(s.substring(last, current));
            sb.append(" ");
            last = current;
        }
        assertEquals(expectedLength * 2, last);
        return sb.toString();
    }
}
