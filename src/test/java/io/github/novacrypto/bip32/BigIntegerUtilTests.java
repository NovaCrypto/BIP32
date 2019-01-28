/*
 *  BIP32 library, a Java implementation of BIP32
 *  Copyright (C) 2017-2019 Alan Evans, NovaCrypto
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

import java.math.BigInteger;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.Assert.assertArrayEquals;

public final class BigIntegerUtilTests {

    @Test
    public void canLeftPad() {
        byte[] target = new byte[5];
        Arrays.fill(target, (byte) 1);
        BigIntegerUtils.ser256(target, BigInteger.ONE);
        assertArrayEquals(new byte[]{0, 0, 0, 0, 1}, target);
    }

    @Test
    public void canFit() {
        for (int i = 0; i < 255; i++) {
            byte[] target = new byte[1];
            Arrays.fill(target, (byte) 1);
            BigIntegerUtils.ser256(target, BigInteger.valueOf(i));
            assertArrayEquals(new byte[]{(byte) i}, target);
        }
    }

    @Test
    public void cantFit() {
        byte[] target = new byte[1];
        assertThatThrownBy(() ->
                BigIntegerUtils.ser256(target, BigInteger.valueOf(256)))
                .hasMessage("ser256 failed, cannot fit integer in buffer");
    }
}