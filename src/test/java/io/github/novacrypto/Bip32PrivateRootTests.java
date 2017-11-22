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

import io.github.novacrypto.bip32.Network;
import io.github.novacrypto.bip32.PrivateKey;
import io.github.novacrypto.bip32.networks.Bitcoin;
import io.github.novacrypto.bip32.networks.Litecoin;
import io.github.novacrypto.bip39.SeedCalculator;
import org.junit.Test;

import static io.github.novacrypto.Asserts.assertBase58KeysEqual;
import static org.junit.Assert.assertEquals;

public final class Bip32PrivateRootTests {

    @Test
    public void bip32RootBitcoinMainnet() {
        assertBip32Root(
                "xprv9s21ZrQH143K49A3PVsMF6DG6RryWeoBaJw1eAmBTn5anZum4AhQDRYH29DMvQ6BY8HWc1jB4vxWPVoD6mmCcN3L3Wf3fq5pQCAA4suatkG",
                "edge talent poet tortoise trumpet dose", Bitcoin.MAIN_NET);
    }

    @Test
    public void bip32RootLitecoinMainnet() {
        assertBip32Root(
                "Ltpv71G8qDifUiNeu7ocqPuyPWS1HhKqbeUWzHxZbf9cTRffoNgdvoTxaGEvyukNo7jNTErngXNhE1fANzvHVtkBFUQg15cDyn8rCan48MF5YP6",
                "edge talent poet tortoise trumpet dose", Litecoin.MAIN_NET);
    }

    @Test
    public void bip32RootBitcoinTestNet() {
        assertBip32Root(
                "tprv8ZgxMBicQKsPexPa44irQjqFQZHBkAqBurr8WbBdwka4aAer3Y39jAuiwKP1vmUVuZpHc7LwEHYJrMLxDz79RRJva9sMLBosKHuaWYn66oB",
                "edge talent poet tortoise trumpet dose", Bitcoin.TEST_NET);
    }

    private void assertBip32Root(String expectedBip32Root, String mnemonic, Network network) {
        final byte[] seed = new SeedCalculator().calculateSeed(mnemonic, "");

        final String actualBip32Root = findBip32Root(seed, network);
        assertBase58KeysEqual(expectedBip32Root, actualBip32Root);
    }

    private String findBip32Root(byte[] seed, Network network) {
        return PrivateKey.fromSeed(seed, network).extendedBase58();
    }
}