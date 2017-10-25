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

import io.github.novacrypto.bip32.networks.Bitcoin;
import io.github.novacrypto.bip39.SeedCalculator;
import org.junit.Ignore;
import org.junit.Test;

import static io.github.novacrypto.base58.Base58.base58Decode;
import static io.github.novacrypto.base58.Base58.base58Encode;
import static io.github.novacrypto.bip32.Hex.toHex;
import static org.junit.Assert.assertEquals;

public final class DeriveNonHardenedTests {

    @Test
    public void deriveFirstIndexNonHardened() {
        assertPrivateKey("xprv9vUtFfdFpb4T59CoQMSLmbpVg1dVZcWXsznR8BVeV4gn7pN1dZa7Kq1VR7fovgbbodEziyyk1i9wrb8wmfwr69DsGsdgV24EtDh5XgzqjHD",
                "edge talent poet tortoise trumpet dose", "m/0", Bitcoin.MAIN_NET);
    }

    @Test
    public void deriveSecondIndexNonHardened() {
        assertPrivateKey("xprv9vUtFfdFpb4T9JCuTLJG1ZBQtno7iBXnH82WzuX9qaAptWEEUDApggPW6A1SSyiunpBjsrLimC1GyV7CPYaG5erJNHTkHBj9QwN9LXw6GTV",
                "edge talent poet tortoise trumpet dose", "m/1", Bitcoin.MAIN_NET);
    }

    private void assertPrivateKey(String expectedBip32Root, String mnemonic, String derivationPath, Network network) {
        final byte[] seed = new SeedCalculator().calculateSeed(mnemonic, "");

        final byte[] bip32Root = findPrivateKey(seed, network, derivationPath);
        final String actualBip32Root = base58Encode(bip32Root).toString();
        assertEquals(toHex(base58Decode(expectedBip32Root)), toHex(base58Decode(actualBip32Root)));
        assertEquals(expectedBip32Root, actualBip32Root);
    }

    private byte[] findPrivateKey(byte[] seed, Network network, String derivationPath) {
        return PrivateRoot.fromSeed(seed, network)
                .cKDpriv(Integer.parseInt(derivationPath.split("/")[1]))
                .toByteArray();
    }
}
