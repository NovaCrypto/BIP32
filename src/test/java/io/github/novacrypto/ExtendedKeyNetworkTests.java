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

import io.github.novacrypto.bip32.ExtendedKey;
import io.github.novacrypto.bip32.Network;
import io.github.novacrypto.bip32.ExtendedPrivateKey;
import io.github.novacrypto.bip32.networks.Bitcoin;
import io.github.novacrypto.bip32.networks.Litecoin;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public final class ExtendedKeyNetworkTests {

    private final ExtendedPrivateKey privateRoot;
    private final Network network;

    @Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
                {Bitcoin.MAIN_NET},
                {Bitcoin.TEST_NET},
                {Litecoin.MAIN_NET},
        });
    }

    public ExtendedKeyNetworkTests(Network network) {
        this.network = network;
        privateRoot = ExtendedPrivateKey.fromSeed(new byte[0], network);
    }

    @Test
    public void canReadDepthOnPrivate() {
        final ExtendedKey derived = privateRoot.derive("m");
        assertEquals(network, derived.network());
    }

    @Test
    public void canReadDepthOnPublic() {
        final ExtendedKey derived = privateRoot.derive("m").neuter();
        assertEquals(network, derived.network());
    }
}