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

import io.github.novacrypto.Hex;
import mockit.integration.junit4.JMockit;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.math.BigInteger;

import static io.github.novacrypto.bip32.FakeSecp256k1SC.fakeGMultiplyAndAddPointNextInfinity;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(JMockit.class)
public final class FakeCurveTests {
    private final byte[] encodedPoint = Hex.toArray("0355fc85b769dd00d4ca22b121504f4b012e146a4ef6c05b31b12c99906aa4d30d");

    @Test
    public void canFakeInfinity() {
        fakeGMultiplyAndAddPointNextInfinity();
        assertTrue(Secp256k1SC.gMultiplyAndAddPoint(BigInteger.ONE, encodedPoint).isInfinity());
    }

    @Test
    public void nextIsNotInfinity() {
        fakeGMultiplyAndAddPointNextInfinity();
        assertTrue(Secp256k1SC.gMultiplyAndAddPoint(BigInteger.ONE, encodedPoint).isInfinity());
        assertFalse(Secp256k1SC.gMultiplyAndAddPoint(BigInteger.ONE, encodedPoint).isInfinity());
    }
}