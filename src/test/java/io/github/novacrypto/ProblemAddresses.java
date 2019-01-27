/*
 *  BIP32 library, a Java implementation of BIP32
 *  Copyright (C) 2017-2019 Alan Evans, NovaCrypto
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
import io.github.novacrypto.bip39.SeedCalculator;
import org.junit.Test;

import static io.github.novacrypto.Asserts.assertBase58AddressEqual;

public final class ProblemAddresses {

    /**
     * This was causing a failure in {@link io.github.novacrypto.bip32.BigIntegerUtils#copyTail}
     */
    @Test
    public void m_86() {
        assertAddress("19h2xXEScYLbSwFCFfJBzBVKoaRcXMsjs3",
                "unique like average east rubber ordinary school hospital phrase",
                "abc",
                "m/86",
                Bitcoin.MAIN_NET);
    }

    private void assertAddress(
            final String expectedAddress,
            final String mnemonic,
            final String passphrase,
            final String derivationPath,
            final Network network) {
        assertBase58AddressEqual(expectedAddress,
                ExtendedPrivateKey.fromSeed(new SeedCalculator().calculateSeed(
                        mnemonic, passphrase),
                        network).derive(derivationPath).neuter().p2pkhAddress());
    }
}
