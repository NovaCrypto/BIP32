/*
 *  BIP32 library, a Java implementation of BIP32
 *  Copyright (C) 2017-2019 Alan Evans, NovaCrypto
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

package io.github.novacrypto.bip32;

import io.github.novacrypto.SuppressFBWarnings;
import mockit.Invocation;
import mockit.Mock;
import mockit.MockUp;

import java.math.BigInteger;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;

final class FakeHmacSha512 {

    static void fakeHmacSha512Responses(BigInteger... responses) {
        byte[][] valuesOfI = new byte[responses.length][];
        for (int i = 0; i < responses.length; i++)
            valuesOfI[i] = toHeadOf64Bytes(responses[i]);
        fakeHmacSha512Responses(valuesOfI);
    }

    static void fakeHmacSha512Responses(byte[]... responses) {
        new MockUp<HmacSha512>() {
            private int i = 0;

            @Mock
            @SuppressFBWarnings(
                    value = "UMAC_UNCALLABLE_METHOD_OF_ANONYMOUS_CLASS",
                    justification = "Found by reflection"
            )
            public byte[] hmacSha512(Invocation inv, final byte[] byteKey, final byte[] seed) {
                if (i > responses.length - 1) {
                    return inv.proceed(byteKey, seed);
                }
                return responses[i++];
            }
        };
    }

    static byte[] toHeadOf64Bytes(BigInteger i) {
        byte[] iBytes = i.toByteArray();
        assertEquals(0, iBytes[0]);
        assertEquals(33, iBytes.length);
        byte[] i32 = Arrays.copyOfRange(iBytes, 1, 33);
        assertEquals(32, i32.length);
        byte[] i64 = new byte[64];
        System.arraycopy(i32, 0, i64, 0, 32);
        return i64;
    }

    static byte[][] toHeadOf64BytesArray(BigInteger... iLs) {
        byte[][] valuesOfI = new byte[iLs.length][];
        for (int i = 0; i < iLs.length; i++)
            valuesOfI[i] = toHeadOf64Bytes(iLs[i]);
        return valuesOfI;
    }
}
