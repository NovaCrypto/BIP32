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

import java.math.BigInteger;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

public final class Secp256k1 {

    //https://en.bitcoin.it/wiki/Secp256k1
    private static BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    private static BigInteger a = new BigInteger("0000000000000000000000000000000000000000000000000000000000000000", 16);
    private static BigInteger b = new BigInteger("0000000000000000000000000000000000000000000000000000000000000007", 16);
    private static BigInteger gx = new BigInteger("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16);
    private static BigInteger gy = new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
    private static ECPoint G = new ECPoint(gx, gy);
    private static BigInteger n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    private static int h = 1;

    static final EllipticCurve curve = new EllipticCurve(new ECFieldFp(p), a, b);

    static final ECParameterSpec spec = new ECParameterSpec(curve, G, n, h);

    public BigInteger getPoint(BigInteger k) {
        return G.getAffineX().multiply(k.mod(n));
    }

    public ECPoint getPointScala(BigInteger k) {
        return scalmult(G, k);
    }

    private static final BigInteger ONE = new BigInteger("1");
    static BigInteger TWO = new BigInteger("2");

   public static ECPoint scalmult(ECPoint P, BigInteger kin){
        //ECPoint R=P; - incorrect
        ECPoint R = ECPoint.POINT_INFINITY,S = P;
        BigInteger k = kin.mod(p);
        int length = k.bitLength();
        //System.out.println("length is" + length);
        byte[] binarray = new byte[length];
        for(int i=0;i<=length-1;i++){
            binarray[i] = k.mod(TWO).byteValue();
            k = k.divide(TWO);
        }
    /*for(int i = length-1;i >= 0;i--){
        System.out.print("" + binarray[i]);
    }*/

        for(int i = length-1;i >= 0;i--){
            // i should start at length-1 not -2 because the MSB of binary may not be 1
            R = doublePoint(R);
            if(binarray[i]== 1)
                R = addPoint(R, S);
        }
        return R;
    }


    public static ECPoint addPoint(ECPoint r, ECPoint s) {

        if (r.equals(s))
            return doublePoint(r);
        else if (r.equals(ECPoint.POINT_INFINITY))
            return s;
        else if (s.equals(ECPoint.POINT_INFINITY))
            return r;
        BigInteger slope = (r.getAffineY().subtract(s.getAffineY())).multiply(r.getAffineX().subtract(s.getAffineX()).modInverse(p)).mod(p);
        BigInteger Xout = (slope.modPow(TWO, p).subtract(r.getAffineX())).subtract(s.getAffineX()).mod(p);
        //BigInteger Yout = r.getAffineY().negate().mod(p); - incorrect
        BigInteger Yout = s.getAffineY().negate().mod(p);
        //Yout = Yout.add(slope.multiply(r.getAffineX().subtract(Xout))).mod(p); - incorrect
        Yout = Yout.add(slope.multiply(s.getAffineX().subtract(Xout))).mod(p);
        ECPoint out = new ECPoint(Xout, Yout);
        return out;
    }

    public static ECPoint doublePoint(ECPoint r) {
        if (r.equals(ECPoint.POINT_INFINITY))
            return r;
        BigInteger slope = (r.getAffineX().pow(2)).multiply(new BigInteger("3"));
        //slope = slope.add(new BigInteger("3")); - incorrect
        slope = slope.add(a);
        slope = slope.multiply((r.getAffineY().multiply(TWO)).modInverse(p));
        BigInteger Xout = slope.pow(2).subtract(r.getAffineX().multiply(TWO)).mod(p);
        BigInteger Yout = (r.getAffineY().negate()).add(slope.multiply(r.getAffineX().subtract(Xout))).mod(p);
        ECPoint out = new ECPoint(Xout, Yout);
        return out;
    }
}
