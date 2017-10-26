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

import org.junit.Test;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.ec.CustomNamedCurves;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.math.ec.FixedPointCombMultiplier;

import java.math.BigInteger;

import static org.junit.Assert.assertEquals;

public final class Secp256k1TestsSponge {


    BigInteger Gx = new BigInteger("55066263022277343669578718895168534326250603453777594175500187360389116729240");
    BigInteger Gy = new BigInteger("32670510020758816978083085130507043184471273380659243275938904335757337482424");
    //        a, b: 0 7
//        h: 1
    BigInteger N = new BigInteger("115792089237316195423570985008687907852837564279074904382605163141518161494337");
    //        get Point input: 392f75ad23278b3cd7b060d900138f20f8cba89abb259b5dcf5d9830b49d8e38
//        Fp:60467516667819882004264915392617288433790568824524844732674277017880552045405 78616888673061828201674833705507548414624840639094893940519153246553790771866
//        Pt:60467516667819882004264915392617288433790568824524844732674277017880552045405 78616888673061828201674833705507548414624840639094893940519153246553790771866
//        Encoded Point: 0285af66cf6924bc0d7d8717f4999e057708bdf4fd5d9730da6f303f3a61847b5d

    X9ECParameters CURVE = CustomNamedCurves.getByName("secp256k1");

    private ECPoint getPointWithCompression(ECPoint point, boolean compressed) {
        if (point.isCompressed() == compressed)
            return point;
        point = point.normalize();
        BigInteger x = point.getAffineXCoord().toBigInteger();
        BigInteger y = point.getAffineYCoord().toBigInteger();
        return CURVE.getCurve().createPoint(x, y, compressed);
    }

    @Test
    public void not_working_as_expected_1() {

        BigInteger input = new BigInteger("25865686353386313737930024219931081678615288876584136840876053493146137235000");

        ECPoint point = getPointWithCompression(new FixedPointCombMultiplier().multiply(CURVE.getG(), input.mod(CURVE.getN())), true);

        assertEquals(new BigInteger("4910749536839409369772420254649277411029444916007512328422778214611734969623"), point.getAffineXCoord().toBigInteger());
        assertEquals(new BigInteger("79730018684873951113339688586093677246953592359416795122351561738439931193345"), point.getAffineYCoord().toBigInteger());
    }

    @Test
    public void not_working_as_expected_2() {

        BigInteger input = new BigInteger("50586395471493885789969809757315971746084953940794436873514397540836228266313");

        ECPoint point = getPointWithCompression(new FixedPointCombMultiplier().multiply(CURVE.getG(), input), true);
        final byte[] encoded = point.getEncoded(true);

        assertEquals(new BigInteger("4910749536839409369772420254649277411029444916007512328422778214611734969623"), point.getAffineXCoord().toBigInteger());
        assertEquals(new BigInteger("79730018684873951113339688586093677246953592359416795122351561738439931193345"), point.getAffineYCoord().toBigInteger());
    }
//
//    @Test
//    public void not_working_as_expected_2() {
//        ECParameterSpec p = ECNamedCurveTable.getParameterSpec("secp256k1");
//
//        BigInteger input = new BigInteger("50586395471493885789969809757315971746084953940794436873514397540836228266313");
//
//        ECPoint point = p.getG().multiply(input);
//
//        assertEquals(new BigInteger("97822910189327572255247885838018517468742632933237251602109122903186873731015"), point.getX().toBigInteger());
//        assertEquals(new BigInteger("39938914926073548725166326311163294251178702163730018003982055639147836320444"), point.getY().toBigInteger());
//    }
//
//    @Test
//    public void not_working_as_expected_1_sponge() {
//        ECParameterSpec p = ECNamedCurveTable.getParameterSpec("secp256k1");
//
//        BigInteger input = new BigInteger("25865686353386313737930024219931081678615288876584136840876053493146137235000");
//
//        ECPoint point = p.getG().multiply(input);
//
//        assertEquals(new BigInteger("4910749536839409369772420254649277411029444916007512328422778214611734969623"), point.getX().toBigInteger());
//        assertEquals(new BigInteger("79730018684873951113339688586093677246953592359416795122351561738439931193345"), point.getY().toBigInteger());
//    }


}
