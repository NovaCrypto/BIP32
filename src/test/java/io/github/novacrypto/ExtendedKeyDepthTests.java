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

package io.github.novacrypto;

import io.github.novacrypto.bip32.ExtendedKey;
import io.github.novacrypto.bip32.PrivateKey;
import io.github.novacrypto.bip32.derivation.Derive;
import io.github.novacrypto.bip32.networks.Bitcoin;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public final class ExtendedKeyDepthTests {

    private static Derive<PrivateKey> privateRoot =
            PrivateKey.fromSeed(new byte[0], Bitcoin.MAIN_NET).derive();

    private final String path;
    private final int expectedDepth;

    @Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
                {"m", 0},
                {"m/0", 1},
                {"m/0'", 1},
                {"m/0/0", 2},
                {"m/0'/0'/0", 3},
        });
    }

    public ExtendedKeyDepthTests(String path, int expectedDepth) {
        this.path = path;
        this.expectedDepth = expectedDepth;
    }

    @Test
    public void canReadDepthOnPrivate() {
        final ExtendedKey derived = privateRoot.derive(path);
        assertEquals(expectedDepth, derived.depth());
    }

    @Test
    public void canReadDepthOnPublic() {
        final ExtendedKey derived = privateRoot.derive(path).neuter();
        assertEquals(expectedDepth, derived.depth());
    }
}