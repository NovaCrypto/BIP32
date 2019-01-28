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

import io.github.novacrypto.bip32.BadKeySerializationException;
import io.github.novacrypto.bip32.Deserializer;
import io.github.novacrypto.bip32.ExtendedPrivateKey;
import io.github.novacrypto.bip32.ExtendedPublicKey;
import io.github.novacrypto.bip32.networks.Bitcoin;
import io.github.novacrypto.bip32.networks.NetworkCollection;
import io.github.novacrypto.bip32.networks.UnknownNetworkException;
import org.junit.Test;

import static io.github.novacrypto.base58.Base58.base58Decode;
import static io.github.novacrypto.hashing.Sha256.sha256Twice;
import static org.assertj.core.api.Java6Assertions.assertThatThrownBy;
import static org.junit.Assert.assertSame;

public final class DeserializerTests {
    private static final String testNetPrivate = "tprv8h32u4uFFpteVm9KA3TJ1QGypPx3AnzQzgp94ViSwtfhBS3vJ8QyxZHXiPi55QpK6fhyB2P8GZJsuersFDEQCABbqLewrA7obiz5jKURc6F";
    private static final String testNetPublic = "tpubDDj53UwVQCaKPEB73h7tQow6PRTyL8BKZzQvM1kkNAU61vJgvXEa93uPtWpsvaMNenwzJztGA9owTgD6rin6PASKDiZHMJCefsEChkEeVWe";

    @Test
    public void deserializePrivateThrowsExceptionWhenNetworkNotFound() {
        final Deserializer<ExtendedPrivateKey> deserializer = ExtendedPrivateKey.deserializer(new NetworkCollection(Bitcoin.MAIN_NET));
        assertThatThrownBy(() ->
                deserializer.deserialize(testNetPrivate)
        ).isInstanceOf(UnknownNetworkException.class);
    }

    @Test
    public void deserializePublicThrowsExceptionWhenNetworkNotFound() {
        final Deserializer<ExtendedPublicKey> deserializer = ExtendedPublicKey.deserializer(new NetworkCollection(Bitcoin.MAIN_NET));
        assertThatThrownBy(() ->
                deserializer.deserialize(testNetPublic)
        ).isInstanceOf(UnknownNetworkException.class);
    }

    @Test
    public void deserializeBadPrivateKeyWhenPaddingExpectedAtPosition45BeforeKeyBytes() {
        final byte[] bytes = base58Decode(testNetPrivate);
        bytes[45] = 1;
        rewriteChecksum(bytes);
        final Deserializer<ExtendedPrivateKey> deserializer = ExtendedPrivateKey.deserializer();
        assertThatThrownBy(() ->
                deserializer.deserialize(bytes)
        ).isInstanceOf(BadKeySerializationException.class)
                .hasMessage("Expected 0 padding at position 45");
    }

    private void rewriteChecksum(byte[] bytes) {
        final byte[] checksum = sha256Twice(bytes, 0, 78);
        System.arraycopy(checksum, 0, bytes, 78, 4);
    }

    @Test
    public void privateKeyDeserializerIsConstant() {
        assertSame(ExtendedPrivateKey.deserializer(), ExtendedPrivateKey.deserializer());
    }

    @Test
    public void publicKeyDeserializerIsConstant() {
        assertSame(ExtendedPublicKey.deserializer(), ExtendedPublicKey.deserializer());
    }

    @Test
    public void anyChangeResultsInChecksumFailurePublicKey() {
        final byte[] bytes = base58Decode(testNetPublic);
        for (int i = 0; i < bytes.length; i++) {
            final byte[] copy = cloneWithMutationAt(bytes, i);
            final Deserializer<ExtendedPublicKey> deserializer = ExtendedPublicKey.deserializer();
            assertThatThrownBy(() ->
                    deserializer.deserialize(copy)
            ).isInstanceOf(BadKeySerializationException.class)
                    .hasMessage("Checksum error");
        }
    }

    @Test
    public void anyChangeResultsInChecksumFailurePrivateKey() {
        final byte[] bytes = base58Decode(testNetPrivate);
        for (int i = 0; i < bytes.length; i++) {
            final byte[] copy = cloneWithMutationAt(bytes, i);
            final Deserializer<ExtendedPrivateKey> deserializer = ExtendedPrivateKey.deserializer();
            assertThatThrownBy(() ->
                    deserializer.deserialize(copy)
            ).isInstanceOf(BadKeySerializationException.class)
                    .hasMessage("Checksum error");
        }
    }

    private static byte[] cloneWithMutationAt(byte[] bytes, int i) {
        final byte[] copy = bytes.clone();
        copy[i] = (byte) ~copy[i];
        return copy;
    }
}