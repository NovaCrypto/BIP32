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
import io.github.novacrypto.bip32.ExtendedPrivateKey;
import io.github.novacrypto.bip32.networks.Bitcoin;
import io.github.novacrypto.bip32.networks.Litecoin;
import io.github.novacrypto.bip39.SeedCalculator;
import org.junit.Test;

import static io.github.novacrypto.Asserts.assertBase58AddressEqual;

public final class P2PKHAddressEncodingTests {

    @Test
    public void m_0_bitcoin_mainnet() {
        assertAddress("1MtBSZjf4b2cJbS688pWq67YHFwUzxn6N3",
                "edge talent poet tortoise trumpet dose", "m/0", Bitcoin.MAIN_NET);
    }

    @Test
    public void m_0_bitcoin_testnet() {
        assertAddress("n2Q8jcpdscTs5huhqhntf1Ks9FYBqifw16",
                "edge talent poet tortoise trumpet dose", "m/0", Bitcoin.TEST_NET);
    }

    @Test
    public void m_1_bitcoin_testnet() {
        assertAddress("mxX3vB7goZq1BcEnhjexisNLXVFhd5VbcP",
                "edge talent poet tortoise trumpet dose", "m/1", Bitcoin.TEST_NET);
    }

    @Test
    public void m_0_litecoin_mainnet() {
        assertAddress("Lg78hn3V9FGfZQ8FJGop77BJVUJm7TmuF3",
                "edge talent poet tortoise trumpet dose", "m/0", Litecoin.MAIN_NET);
    }


    @Test
    public void m_44h_0_bitcoin_mainnet() {
        assertAddress("1CswTrmVUYb8r4761WFhezWCeBr9NC7ckz",
                "edge talent poet tortoise trumpet dose", "m/44'/0", Bitcoin.MAIN_NET);
    }

    @Test
    public void m_44h_0h_0_bitcoin_mainnet() {
        assertAddress("1Lqauvix2LywKU3FsUFqdGaWuJkTyiBQjE",
                "edge talent poet tortoise trumpet dose", "m/44'/0'/0", Bitcoin.MAIN_NET);
    }

    @Test
    public void m_44h_0h_0h_0_bitcoin_mainnet() {
        assertAddress("1ET4ePzE8ZVu629Y7wMzMNGaAxU69dZorY",
                "edge talent poet tortoise trumpet dose", "m/44'/0'/0'/0", Bitcoin.MAIN_NET);
    }

    @Test
    public void m_44h_0h_0h_0_0_bitcoin_mainnet() {
        assertAddress("1HprbmKJnHmDQDjTjDYXu5KJzPTrKaKjFF",
                "edge talent poet tortoise trumpet dose", "m/44'/0'/0'/0/0", Bitcoin.MAIN_NET);
    }

    private void assertAddress(
            final String expectedAddress,
            final String mnemonic,
            final String derivationPath,
            final Network network) {
        assertBase58AddressEqual(expectedAddress,
                ExtendedPrivateKey.fromSeed(new SeedCalculator().calculateSeed(
                        mnemonic, ""),
                        network).derive(derivationPath).neuter().p2pkhAddress());
    }


}
