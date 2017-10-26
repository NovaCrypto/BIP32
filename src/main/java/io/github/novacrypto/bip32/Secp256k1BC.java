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

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.ec.CustomNamedCurves;

import java.math.BigInteger;

import static io.github.novacrypto.bip32.BigIntegerUtils.getBigInteger;

public class Secp256k1BC {

    private final X9ECParameters CURVE = CustomNamedCurves.getByName("secp256k1");
    private final ECParameterSpec p = ECNamedCurveTable.getParameterSpec("secp256k1");
    private final ECCurve curve = p.getCurve();
    private final ECPoint G = p.getG();

    public ECPoint getG() {
        return G;
    }

    public BigInteger getN() {
        return p.getN();
    }

    public int getFieldSize() {
        return p.getCurve().getFieldSize();
    }

    public ECCurve getCurve() {
        return curve;
    }

    public byte[] getPoint(final byte[] bytes) {
        final BigInteger q = getBigInteger(bytes);

        org.spongycastle.math.ec.ECPoint point2 = CURVE.getG().multiply(q);

        final ECPoint point = G.multiply(q);

        System.out.println("G: " + G.getX().toBigInteger() + " " + G.getY().toBigInteger());
        System.out.println("a,b: " + curve.getA().toBigInteger() + " " + curve.getB().toBigInteger());
        System.out.println("h: " + p.getH());
        System.out.println("N: " + getN());
        System.out.println("get Point input: " + toHex(bytes));
        System.out.println("get Point input: " + q);

        final ECPoint.Fp fp = new ECPoint.Fp(point.getCurve(), point.getX(), point.getY(), true);

        System.out.println("Fp:" + fp.getX().toBigInteger() + " " + fp.getY().toBigInteger());
        System.out.println("Pt:" + point.getX().toBigInteger() + " " + point.getY().toBigInteger());
        System.out.println("P2:" + point2.getX().toBigInteger() + " " + point2.getY().toBigInteger());
        //System.out.println("P2:" + point2.getAffineXCoord().toBigInteger() + " " + point2.getAffineYCoord().toBigInteger());

        final byte[] encoded = point2.getEncoded(true);

        System.out.println("Encoded Point: " + toHex(fp.getEncoded()));
        System.out.println("Encoded Point: " + toHex(encoded));
        System.out.println();

        return encoded;
    }


    public static String toHex(byte[] array) {
        final BigInteger bi = new BigInteger(1, array);
        final String hex = bi.toString(16);
        final int paddingLength = (array.length * 2) - hex.length();
        if (paddingLength > 0) {
            return String.format("%0" + paddingLength + "d", 0) + hex;
        } else {
            return hex;
        }
    }
}
