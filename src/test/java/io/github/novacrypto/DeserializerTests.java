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

import io.github.novacrypto.bip32.Deserializer;
import io.github.novacrypto.bip32.PrivateKey;
import io.github.novacrypto.bip32.PublicKey;
import io.github.novacrypto.bip32.networks.Bitcoin;
import io.github.novacrypto.bip32.networks.NetworkCollection;
import io.github.novacrypto.bip32.networks.UnknownNetworkException;
import org.junit.Test;

import static org.assertj.core.api.Java6Assertions.assertThatThrownBy;
import static org.junit.Assert.assertSame;

public final class DeserializerTests {

    @Test
    public void deserializePrivateThrowsExceptionWhenNetworkNotFound() {
        final String testNetPrivate = "tprv8h32u4uFFpteVm9KA3TJ1QGypPx3AnzQzgp94ViSwtfhBS3vJ8QyxZHXiPi55QpK6fhyB2P8GZJsuersFDEQCABbqLewrA7obiz5jKURc6F";
        final Deserializer<PrivateKey> deserializer = PrivateKey.deserializer(new NetworkCollection(Bitcoin.MAIN_NET));
        assertThatThrownBy(() ->
                deserializer.deserialize(testNetPrivate)
        ).isInstanceOf(UnknownNetworkException.class);
    }

    @Test
    public void deserializePublicThrowsExceptionWhenNetworkNotFound() {
        final String testNetPublic = "tpubDDj53UwVQCaKPEB73h7tQow6PRTyL8BKZzQvM1kkNAU61vJgvXEa93uPtWpsvaMNenwzJztGA9owTgD6rin6PASKDiZHMJCefsEChkEeVWe";
        final Deserializer<PublicKey> deserializer = PublicKey.deserializer(new NetworkCollection(Bitcoin.MAIN_NET));
        assertThatThrownBy(() ->
                deserializer.deserialize(testNetPublic)
        ).isInstanceOf(UnknownNetworkException.class);
    }

    @Test
    public void privateKeyDeserializerIsConstant() {
        assertSame(PrivateKey.deserializer(), PrivateKey.deserializer());
    }

    @Test
    public void publicKeyDeserializerIsConstant() {
        assertSame(PublicKey.deserializer(), PublicKey.deserializer());
    }
}