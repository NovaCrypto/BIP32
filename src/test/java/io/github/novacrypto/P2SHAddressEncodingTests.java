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

import static io.github.novacrypto.Asserts.assertBase58AddressEqual;

public final class P2SHAddressEncodingTests {

    @Test
    public void m_49h_0h_0h_0_0_bitcoin_mainnet() {
        assertAddress("33iHU3tmRFrkA8sSg1AzjxBNXbCmMPq7CY",
                "edge talent poet tortoise trumpet dose", "m/49'/0'/0'/0/0", Bitcoin.MAIN_NET);
    }

    @Test
    public void m_49h_0h_0h_0_0_bitcoin_testnet() {
        assertAddress("2N2xMMnk8C6i3LSdUtAfeJxXPeczzKW7ecw",
                "edge talent poet tortoise trumpet dose", "m/49'/1'/0'/0/0", Bitcoin.TEST_NET);
    }

    @Test
    public void m_49h_0h_0h_0_0_litecoin_mainnet() {
        assertAddress("MGnFY7fD3Ht9zWm6XU9SGAXEkDGzjiyy7P",
                "edge talent poet tortoise trumpet dose", "m/49'/2'/0'/0/0", Litecoin.MAIN_NET);
    }

    private void assertAddress(
            final String expectedAddress,
            final String mnemonic,
            final String derivationPath,
            final Network network) {
        assertBase58AddressEqual(expectedAddress,
                PrivateKey.fromSeed(new SeedCalculator().calculateSeed(
                        mnemonic, ""),
                        network).derive(derivationPath).neuter().p2shAddress());
    }
}