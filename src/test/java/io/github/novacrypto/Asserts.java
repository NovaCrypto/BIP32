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

import static io.github.novacrypto.base58.Base58.base58Decode;
import static io.github.novacrypto.Hex.toHex;
import static org.junit.Assert.assertEquals;

public final class Asserts {

    /**
     * Compares two base58 keys. On failure, shows hex comparison.
     *
     * @param expectedKey Base58 string of expected key
     * @param actualKey   Base58 string of actual key
     */
    public static void assertBase58KeysEqual(String expectedKey, String actualKey) {
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

    private static int indexOfFirstDifference(String a, String b) {
        final int length = Math.min(a.length(), b.length());
        for (int i = 0; i < length; i++) {
            if (a.charAt(i) != b.charAt(i)) return i;
        }
        return length;
    }

    private static String decodeKey(String expectedBase58Key) {
        final String s = toHex(base58Decode(expectedBase58Key));
        assertEquals(s.length(), 164);
        StringBuilder sb = new StringBuilder();
        int[] indexes = new int[]{4, 1, 4, 4, 32, 33, 4};
        int last = 0;
        for (int index : indexes) {
            final int current = last + index * 2;
            sb.append(s.substring(last, current));
            sb.append(" ");
            last = current;
        }
        assertEquals(164, last);
        return sb.toString();
    }
}
