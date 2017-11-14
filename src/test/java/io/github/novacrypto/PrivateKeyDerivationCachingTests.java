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

import io.github.novacrypto.bip32.CharSequenceDerivation;
import io.github.novacrypto.bip32.Derivation;
import io.github.novacrypto.bip32.IntArrayDerivation;
import io.github.novacrypto.bip32.PrivateKey;
import io.github.novacrypto.bip32.networks.Bitcoin;
import org.junit.Test;

import static io.github.novacrypto.base58.Base58.base58Encode;
import static io.github.novacrypto.bip32.Index.hard;
import static io.github.novacrypto.bip32.KeyCacheDecorator.newCacheOf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;

public final class PrivateKeyDerivationCachingTests {

    @Test
    public void root() {
        assertEqualPathsSame("m", new int[0]);
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
        final Derivation.Visitor<PrivateKey> cache = newCacheOf(PrivateKey.DERIVATION_VISITOR);
        final PrivateKey privateKey = PrivateKey.fromSeed(new byte[1], Bitcoin.MAIN_NET);
        assertEqualPathSame("m/0", new int[]{0}, cache, privateKey);
        assertEqualPathSame("m/1", new int[]{1}, cache, privateKey);
    }

    private static void assertEqualPathsSame(String derivationPath, int[] path) {
        final Derivation.Visitor<PrivateKey> cache = newCacheOf(PrivateKey.DERIVATION_VISITOR);
        assertEqualPathSame(derivationPath, path, cache);
    }

    private static void assertEqualPathSame(String derivationPath, int[] path, Derivation.Visitor<PrivateKey> cache) {
        final PrivateKey privateKey = PrivateKey.fromSeed(new byte[1], Bitcoin.MAIN_NET);
        assertEqualPathSame(derivationPath, path, cache, privateKey);
    }

    private static void assertEqualPathSame(String derivationPath, int[] path, Derivation.Visitor<PrivateKey> cache, PrivateKey root) {
        assertEquals(
                "Without cache",
                base58Encode(root.derive(derivationPath).toByteArray()),
                base58Encode(root.derive(derivationPath, CharSequenceDerivation.INSTANCE, cache).toByteArray())
        );
        assertEquals(
                "Equal with different derivations",
                base58Encode(root.derive(derivationPath, CharSequenceDerivation.INSTANCE, cache).toByteArray()),
                base58Encode(root.derive(path, IntArrayDerivation.INSTANCE, cache).toByteArray())
        );
        assertSame(
                "Same by cache",
                root.derive(derivationPath, CharSequenceDerivation.INSTANCE, cache),
                root.derive(path, IntArrayDerivation.INSTANCE, cache)
        );
        assertSame(
                "Same without specifying derivation",
                root.derive(derivationPath, cache),
                root.derive(derivationPath, CharSequenceDerivation.INSTANCE, cache)
        );
    }
}