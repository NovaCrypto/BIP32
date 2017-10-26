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

final class BigIntegerUtils {

    static BigInteger getBigInteger(byte[] bytes) {
        //TODO: Needs to be more efficient, like negate +1
        byte[] bytes2 = new byte[bytes.length + 1];
        System.arraycopy(bytes, 0, bytes2, 1, bytes.length);
        BigInteger q = new BigInteger(bytes2);
        if (q.signum() < 0) throw new RuntimeException("neg big i");
        return q;
    }
}
