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

import io.github.novacrypto.bip32.networks.*;
import org.junit.Test;

import static org.assertj.core.api.Java6Assertions.assertThatThrownBy;
import static org.junit.Assert.assertSame;

public final class NetworkCollectionTests {

    @Test
    public void canFindByPrivate() {
        final NetworkCollection collection = new NetworkCollection(Bitcoin.MAIN_NET);
        assertSame(Bitcoin.MAIN_NET,
                collection.findByPrivateVersion(Bitcoin.MAIN_NET.getPrivateVersion())
        );
    }

    @Test
    public void canFindByPrivateTwoEntries() {
        final NetworkCollection collection = new NetworkCollection(Bitcoin.MAIN_NET, Bitcoin.TEST_NET);
        assertSame(Bitcoin.TEST_NET,
                collection.findByPrivateVersion(Bitcoin.TEST_NET.getPrivateVersion())
        );
    }

    @Test
    public void throwsWhenCantFindByPrivate() {
        final NetworkCollection collection = new NetworkCollection(Bitcoin.MAIN_NET);
        assertThatThrownBy(() ->
                collection.findByPrivateVersion(Bitcoin.TEST_NET.getPrivateVersion())
        )
                .isInstanceOf(UnknownNetworkException.class)
                .hasMessage("Can't find network that matches private version 0x4358394");
    }

    @Test
    public void throwsWhenCantFindByPrivateAlternativeMessageExpected() {
        final NetworkCollection collection = new NetworkCollection(Bitcoin.TEST_NET);
        assertThatThrownBy(() ->
                collection.findByPrivateVersion(Bitcoin.MAIN_NET.getPrivateVersion())
        )
                .isInstanceOf(UnknownNetworkException.class)
                .hasMessage("Can't find network that matches private version 0x488ade4");
    }

    @Test
    public void defaultCollectionCanFindBitcoin() {
        assertSame(Bitcoin.MAIN_NET,
                DefaultNetworks.INSTANCE.findByPrivateVersion(Bitcoin.MAIN_NET.getPrivateVersion())
        );
    }

    @Test
    public void defaultCollectionCanFindLitecoin() {
        assertSame(Litecoin.MAIN_NET,
                DefaultNetworks.INSTANCE.findByPrivateVersion(Litecoin.MAIN_NET.getPrivateVersion())
        );
    }

    @Test
    public void defaultCollectionCanFindBitcoinTestNet() {
        assertSame(Bitcoin.TEST_NET,
                DefaultNetworks.INSTANCE.findByPrivateVersion(Bitcoin.TEST_NET.getPrivateVersion())
        );
    }
}