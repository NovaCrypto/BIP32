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

import org.junit.Ignore;
import org.junit.Test;

import java.math.BigInteger;

import static io.github.novacrypto.base58.Base58.base58Encode;
import static io.github.novacrypto.bip32.Hex.toHex;
import static org.junit.Assert.assertEquals;

public final class Secp256k1Bouncy {

    @Test
    public void compare() {
        final BigInteger x = new BigInteger("0279BE667EF9DCBBAC55A06295CE870B07029BFCAA2DCE28D959F2815B16F81798", 16);
        assertEquals(base58Encode(new Secp256k1BC().getPoint(x).getEncoded()),
                base58Encode(new Secp256k1().getPoint(x).toByteArray()));

    }

    @Test
    public void compare2() {
        final BigInteger x = new BigInteger("50586395471493885789969809757315971746084953940794436873514397540836228266313", 16);
        assertEquals(new BigInteger("97822910189327572255247885838018517468742632933237251602109122903186873731015", 10),
                new Secp256k1BC().getPoint(x).getX().toBigInteger());
    }

    @Test
    public void compare2X() {
        final BigInteger x = new BigInteger("50586395471493885789969809757315971746084953940794436873514397540836228266313", 16);
        assertEquals(new BigInteger("97822910189327572255247885838018517468742632933237251602109122903186873731015", 10),
                new Secp256k1().getPointScala(x).getAffineX());
    }
}
