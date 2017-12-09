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

import mockit.Invocation;
import mockit.Mock;
import mockit.MockUp;
import org.spongycastle.math.ec.ECPoint;

import java.math.BigInteger;

final class FakeSecp256k1SC {

    static void fakeGMultiplyAndAddPoint(ECPoint... responses) {
        new MockUp<Secp256k1SC>() {
            private int i = 0;

            @Mock
            public ECPoint gMultiplyAndAddPoint(final Invocation inv, final BigInteger p, final byte[] toAdd) {
                if (i > responses.length - 1) {
                    return inv.proceed(p, toAdd);
                }
                return responses[i++];
            }
        };
    }

    static void fakeGMultiplyAndAddPointNextInfinity() {
        fakeGMultiplyAndAddPoint(Secp256k1SC.CURVE.getCurve().getInfinity());
    }
}