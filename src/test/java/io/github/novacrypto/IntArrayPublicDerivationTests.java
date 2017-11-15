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

import io.github.novacrypto.bip32.derivation.Derive;
import io.github.novacrypto.bip32.derivation.IntArrayDerivation;
import io.github.novacrypto.bip32.PrivateKey;
import io.github.novacrypto.bip32.PublicKey;
import io.github.novacrypto.bip32.networks.Bitcoin;
import org.junit.Test;

import static io.github.novacrypto.base58.Base58.base58Encode;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;

public final class IntArrayPublicDerivationTests {

    @Test
    public void root() {
        assertEqualPaths("m", new int[0]);
    }

    @Test
    public void oneLevelDeep() {
        assertEqualPaths("m/1", new int[]{1});
    }

    @Test
    public void fourLevelsDeep() {
        assertEqualPaths("m/0/1/2/3", new int[]{0, 1, 2, 3});
    }

    @Test
    public void deriveIsNotCached() {
        final Derive<PublicKey> privateKey = createPrivateKey().neuter().derive();
        assertNotSame(privateKey.derive("m/0"), privateKey.derive(new int[]{0}, IntArrayDerivation.INSTANCE));
    }

    private static PrivateKey createPrivateKey() {
        return PrivateKey.fromSeed(new byte[1], Bitcoin.MAIN_NET);
    }

    private static void assertEqualPaths(String derivationPath, int[] path) {
        final PublicKey privateKey = createPrivateKey().neuter();
        assertEquals(
                base58Encode(privateKey.derive(derivationPath).toByteArray()),
                base58Encode(privateKey.derive(path, IntArrayDerivation.INSTANCE).toByteArray())
        );
    }
}