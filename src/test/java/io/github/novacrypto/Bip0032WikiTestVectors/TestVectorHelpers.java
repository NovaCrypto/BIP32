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

package io.github.novacrypto.Bip0032WikiTestVectors;

import io.github.novacrypto.bip32.PrivateKey;
import io.github.novacrypto.bip32.ToByteArray;
import io.github.novacrypto.bip32.networks.Bitcoin;

import static io.github.novacrypto.Asserts.assertBase58KeysEqual;
import static io.github.novacrypto.Hex.toArray;
import static io.github.novacrypto.base58.Base58.base58Encode;

final class TestVectorHelpers {

    static void assertBase58(String expectedBase58,
                             ToByteArray toByteArray) {
        assertBase58KeysEqual(expectedBase58,
                base58Encode(toByteArray
                        .toByteArray()).toString());
    }

    static int hard(int i) {
        return i | 0x80000000;
    }

    static PrivateKey createMainNetRootFromSeed(String seed) {
        return PrivateKey.fromSeed(toArray(
                seed
        ), Bitcoin.MAIN_NET);
    }
}
