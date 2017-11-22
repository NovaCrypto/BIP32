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
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

public final class SerializerBadDataTests {

    @Test
    public void cantSerializeNullChainCode() {
        final Serializer serializer = new Serializer.Builder()
                .build();
        assertThatThrownBy(() -> serializer.serialize(new byte[32], null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Chain code is null");
    }

    @Test
    public void cantSerializeNullKey() {
        final Serializer serializer = new Serializer.Builder()
                .build();
        assertThatThrownBy(() -> serializer.serialize(null, new byte[32]))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Key is null");
    }

    @Test
    public void cantSerializeIfChainCodeIsWrongLength() {
        final Serializer serializer = new Serializer.Builder()
                .build();
        assertThatThrownBy(() -> serializer.serialize(new byte[32], new byte[33]))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Chain code must be 32 bytes");
    }

    @Test
    public void cantSerializeIfKeyIsWrongLengthForUnNeutered() {
        final Serializer serializer = new Serializer.Builder()
                .neutered(false)
                .build();
        assertThatThrownBy(() -> serializer.serialize(new byte[33], new byte[32]))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Key must be 32 bytes for non neutered serialization");
    }

    @Test
    public void cantSerializeIfKeyIsWrongLengthForNeutered() {
        final Serializer serializer = new Serializer.Builder()
                .neutered(true)
                .build();
        assertThatThrownBy(() -> serializer.serialize(new byte[32], new byte[32]))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Key must be 33 bytes for neutered serialization");
    }

    @Test
    public void cantCreateSerializerIfDepthIsNegative() {
        final Serializer.Builder builder = new Serializer.Builder();
        assertThatThrownBy(() -> builder.depth(-1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Depth must be [0..255]");
    }

    @Test
    public void cantCreateSerializerIfDepthIsAbove255() {
        final Serializer.Builder builder = new Serializer.Builder();
        assertThatThrownBy(() -> builder.depth(256))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Depth must be [0..255]");
    }

    @Test
    public void canCreateSerializerInAllValidDepthRanges() {
        for (int i = 0; i <= 255; i++)
            new Serializer.Builder()
                    .network(Bitcoin.MAIN_NET)
                    .depth(255)
                    .build();
    }
}