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

package io.github.novacrypto.bip32;

import mockit.integration.junit4.JMockit;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.math.BigInteger;
import java.util.Arrays;

import static io.github.novacrypto.bip32.FakeHmacSha512.fakeHmacResponses;
import static io.github.novacrypto.bip32.FakeHmacSha512.toHeadOf64Bytes;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;

@RunWith(JMockit.class)
public final class FakeHmacSha512Tests {
    @Test
    public void canFakeHmacResponses() {
        byte[] one = new byte[100];
        byte[] two = new byte[100];
        fakeHmacResponses(one, two);
        assertSame(one, HmacSha512.hmacSha512(new byte[0], new byte[0]));
        assertSame(two, HmacSha512.hmacSha512(new byte[0], new byte[0]));
    }

    @Test
    public void canCreate64BytesBasedOnN() {
        BigInteger n = Secp256k1SC.n();
        byte[] n64 = toHeadOf64Bytes(n);
        assertEquals(n, new BigInteger(1, Arrays.copyOfRange(n64, 0, 32)));
    }

    @Test
    public void canCreate64BytesBasedOnNPlus1() {
        BigInteger nPlus1 = Secp256k1SC.n().add(BigInteger.ONE);
        byte[] nPlus1_64 = toHeadOf64Bytes(nPlus1);
        assertEquals(nPlus1, new BigInteger(1, Arrays.copyOfRange(nPlus1_64, 0, 32)));
    }
}