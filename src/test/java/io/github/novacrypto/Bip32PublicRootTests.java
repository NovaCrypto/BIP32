/*
 *  BIP32 library, a Java implementation of BIP32
 *  Copyright (C) 2017-2018 Alan Evans, NovaCrypto
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
import io.github.novacrypto.bip32.ExtendedPrivateKey;
import io.github.novacrypto.bip32.ExtendedPublicKey;
import io.github.novacrypto.bip32.networks.Bitcoin;
import io.github.novacrypto.bip32.networks.Litecoin;
import io.github.novacrypto.bip39.SeedCalculator;
import org.junit.Test;

import static io.github.novacrypto.Asserts.assertBase58KeysEqual;

public final class Bip32PublicRootTests {

    @Test
    public void bip32RootBitcoinMainnet() {
        assertBip32Root(
                "xpub661MyMwAqRbcGdEWVXQMcE9zeThTv7X2wXrcSZAo27cZfNEubi1emDrksQppSupTfsNcsu9cyHP7pxEraUrYinxcMjgNLcH4N6Kagd1jrrc",
                "edge talent poet tortoise trumpet dose", Bitcoin.MAIN_NET);
    }

    @Test
    public void bip32RootLitecoinMainnet() {
        assertBip32Root(
                "Ltub2SSUS19CirucWzWT61QMU6GDjG22fu3B4p4bGduuPcTGPjsiFiWPasMCEHLr7KDiG5nCU2YApK2Vw3byVNwzZik2esZq1J36rb5vbCeXoSK",
                "edge talent poet tortoise trumpet dose", Litecoin.MAIN_NET);
    }

    @Test
    public void bip32RootBitcoinTestNet() {
        assertBip32Root(
                "tpubD6NzVbkrYhZ4YRRMwiPSp9VMyao7uW26VASuo7DwN2NTQeucfvrjufXb7SubyQmhTmuXVUfVWPDAX8jTyLhncEQuRLRg28wHx3uzSiPBDzL",
                "edge talent poet tortoise trumpet dose", Bitcoin.TEST_NET);
    }

    private void assertBip32Root(String expectedBip32Root, String mnemonic, Network network) {
        final byte[] seed = new SeedCalculator().calculateSeed(mnemonic, "");

        final String actualBip32Root = findBip32Root(seed, network);
        assertBase58KeysEqual(expectedBip32Root, actualBip32Root);
    }

    private String findBip32Root(byte[] seed, Network network) {
        final ExtendedPrivateKey privateKey = ExtendedPrivateKey.fromSeed(seed, network);
        final ExtendedPublicKey neutered = privateKey.neuter();
        return neutered.extendedBase58();
    }
}