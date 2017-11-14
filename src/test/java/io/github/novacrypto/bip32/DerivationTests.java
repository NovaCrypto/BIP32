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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static io.github.novacrypto.bip32.Index.hard;
import static org.junit.Assert.assertEquals;

public final class DerivationTests {

    @Test
    public void split_m() {
        assertEquals(Collections.emptyList(), derive("m"));
    }

    @Test
    public void split_m_0() {
        assertEquals(Collections.singletonList(0), derive("m/0"));
    }

    @Test
    public void split_m_1() {
        assertEquals(Collections.singletonList(1), derive("m/1"));
    }

    @Test
    public void split_m_0_0() {
        assertEquals(Arrays.asList(0, 0), derive("m/0/0"));
    }

    @Test
    public void split_0h() {
        assertEquals(Collections.singletonList(hard(0)), derive("m/0'"));
    }

    @Test
    public void split_12h() {
        assertEquals(Collections.singletonList(hard(12)), derive("m/12'"));
    }

    @Test
    public void split_123h_456() {
        assertEquals(Arrays.asList(hard(123), 456), derive("m/123'/456"));
    }

    private static List<Integer> derive(CharSequence derivationPath) {
        final Integer[] parts = CharSequenceDerivation.INSTANCE
                .derive(new Integer[0], derivationPath, DerivationTests::concat);
        return Arrays.asList(parts);
    }

    private static Integer[] concat(Integer[] input, int index) {
        final Integer[] integers = Arrays.copyOf(input, input.length + 1);
        integers[input.length] = index;
        return integers;
    }
}