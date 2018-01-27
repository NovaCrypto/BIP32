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
import io.github.novacrypto.bip32.ExtendedPrivateKey;
import io.github.novacrypto.bip32.derivation.Derive;
import io.github.novacrypto.bip32.networks.Bitcoin;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.util.Arrays;
import java.util.Collection;

import static io.github.novacrypto.bip32.Index.hard;
import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public final class ExtendedKeyChildNumberTests {

    private static Derive<ExtendedPrivateKey> privateRoot =
            ExtendedPrivateKey.fromSeed(new byte[0], Bitcoin.MAIN_NET).derive();

    private final String path;
    private final int expectedChildNumber;

    @Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
                {"m", 0},
                {"m/0", 0},
                {"m/0'", hard(0)},
                {"m/0/0", 0},
                {"m/0'/0'/0", 0},
                {"m/0'/0'/1", 1},
                {"m/0'/0'/1'", hard(1)},
                {"m/0'/0'/1'/456", 456},
        });
    }

    public ExtendedKeyChildNumberTests(String path, int expectedChildNumber) {
        this.path = path;
        this.expectedChildNumber = expectedChildNumber;
    }


    @Test
    public void canReadChildNumberOnPrivate() {
        final ExtendedKey derived = privateRoot.derive(path);
        assertEquals(expectedChildNumber, derived.childNumber());
    }

    @Test
    public void canReadChildNumberOnPublic() {
        final ExtendedKey derived = privateRoot.derive(path).neuter();
        assertEquals(expectedChildNumber, derived.childNumber());
    }
}