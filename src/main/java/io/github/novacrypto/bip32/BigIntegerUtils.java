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
import java.util.Arrays;

final class BigIntegerUtils {

    static BigInteger parse256(final byte[] bytes) {
        return new BigInteger(1, bytes);
    }

    static byte[] ser256(final BigInteger integer, final int length) {
        final byte[] modArr = integer.toByteArray();
        final byte[] target = new byte[length];
        copyTail(modArr, target);
        Arrays.fill(modArr, (byte) 0);
        return target;
    }

    private static void copyTail(final byte[] src, final byte[] dest) {
        final int start = src.length - dest.length;
        //TODO: expect this to fail when the source.length < dest.length
        System.arraycopy(src, start, dest, 0, dest.length);
    }
}