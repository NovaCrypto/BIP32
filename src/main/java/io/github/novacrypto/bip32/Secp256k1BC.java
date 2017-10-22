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

import java.math.BigInteger;

public class Secp256k1BC {

    private final ECParameterSpec p = ECNamedCurveTable.getParameterSpec("secp256k1");
    private final ECCurve curve = p.getCurve();
    private final ECPoint G = p.getG();

    public ECPoint getPoint(final BigInteger k) {
        return G.multiply(k.mod(p.getN()));
    }

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

    public byte[] getPoint(byte[] bytes) {
        ECPoint point = new Secp256k1BC().getPoint(new BigInteger(bytes));
        return new ECPoint.Fp(point.getCurve(), point.getX(), point.getY(), true).getEncoded();
    }
}
