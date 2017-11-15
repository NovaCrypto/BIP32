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

import io.github.novacrypto.bip32.derivation.CharSequenceDerivation;
import io.github.novacrypto.bip32.derivation.Derive;
import io.github.novacrypto.bip32.derivation.IntArrayDerivation;
import io.github.novacrypto.bip32.PrivateKey;
import io.github.novacrypto.bip32.networks.Bitcoin;
import org.junit.Test;

import static io.github.novacrypto.base58.Base58.base58Encode;
import static io.github.novacrypto.bip32.Index.hard;
import static org.junit.Assert.*;

public final class PrivateKeyDerivationCachingTests {

    @Test
    public void root() {
        assertCached("m", new int[0], createPrivateKey().deriveWithCache());
    }

    @Test
    public void oneLevelDeep() {
        assertEqualPathsSame("m/1", new int[]{1});
    }

    @Test
    public void fourLevelsDeep() {
        assertEqualPathsSame("m/0/1/2/3", new int[]{0, 1, 2, 3});
    }

    @Test
    public void sameChildIndexes() {
        assertEqualPathsSame("m/0/0/0/0", new int[]{0, 0, 0, 0});
    }

    @Test
    public void hardIndexes() {
        assertEqualPathsSame("m/44'/0'/0'/0/4", new int[]{hard(44), hard(0), hard(0), 0, 4});
    }

    @Test
    public void noCacheHitOnParent() {
        final Derive<PrivateKey> privateKey = createPrivateKey().deriveWithCache();
        assertCached("m/0", new int[]{0}, privateKey);
        assertCached("m/1", new int[]{1}, privateKey);
    }

    private static void assertEqualPathsSame(String derivationPath, int[] path) {
        final PrivateKey privateKey = createPrivateKey();
        assertNotCached(derivationPath, path, privateKey);
        assertNotCached(derivationPath, path, privateKey.derive());
        assertCached(derivationPath, path, privateKey.deriveWithCache());
    }

    private static PrivateKey createPrivateKey() {
        return PrivateKey.fromSeed(new byte[1], Bitcoin.MAIN_NET);
    }

    private static void assertNotCached(String derivationPath, int[] path, Derive<PrivateKey> rootNonCache) {
        assertEquals(
                base58Encode(rootNonCache.derive(derivationPath).toByteArray()),
                base58Encode(rootNonCache.derive(derivationPath, CharSequenceDerivation.INSTANCE).toByteArray())
        );
        assertEquals(
                base58Encode(rootNonCache.derive(derivationPath, CharSequenceDerivation.INSTANCE).toByteArray()),
                base58Encode(rootNonCache.derive(path, IntArrayDerivation.INSTANCE).toByteArray())
        );
        assertNotSame(
                rootNonCache.derive(derivationPath, CharSequenceDerivation.INSTANCE),
                rootNonCache.derive(path, IntArrayDerivation.INSTANCE)
        );
    }

    private static void assertCached(String derivationPath, int[] path, Derive<PrivateKey> rootCache) {
        assertEquals(
                base58Encode(rootCache.derive(derivationPath).toByteArray()),
                base58Encode(rootCache.derive(derivationPath, CharSequenceDerivation.INSTANCE).toByteArray())
        );
        assertEquals(
                base58Encode(rootCache.derive(derivationPath, CharSequenceDerivation.INSTANCE).toByteArray()),
                base58Encode(rootCache.derive(path, IntArrayDerivation.INSTANCE).toByteArray())
        );
        assertSame(
                rootCache.derive(derivationPath, CharSequenceDerivation.INSTANCE),
                rootCache.derive(path, IntArrayDerivation.INSTANCE)
        );
        assertSame(
                rootCache.derive(derivationPath),
                rootCache.derive(derivationPath, CharSequenceDerivation.INSTANCE)
        );
    }
}