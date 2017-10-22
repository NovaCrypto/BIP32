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
import io.github.novacrypto.bip32.PublicKey;
import io.github.novacrypto.bip32.networks.Bitcoin;
import io.github.novacrypto.bip32.networks.Litecoin;
import io.github.novacrypto.bip39.SeedCalculator;
import org.junit.Test;

import static io.github.novacrypto.Asserts.assertBase58KeysEqual;
import static io.github.novacrypto.base58.Base58.base58Encode;

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
                "xpub661MyMwAqRbcGdEWVXQMcE9zeThTv7X2wXrcSZAo27cZfNEubi1emDrksQppSupTfsNcsu9cyHP7pxEraUrYinxcMjgNLcH4N6Kagd1jrrc",
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

        final byte[] bip32Root = findBip32Root(seed, network);
        final String actualBip32Root = base58Encode(bip32Root).toString();
        assertBase58KeysEqual(expectedBip32Root, actualBip32Root);
    }

    private byte[] findBip32Root(byte[] seed, Network network) {
        final PrivateKey privateKey = PrivateKey.fromSeed(seed, network);
        final PublicKey neutered = privateKey.neuter();
        return neutered.toByteArray();
    }
}