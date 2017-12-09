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
import mockit.integration.junit4.JMockit;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.math.BigInteger;

import static io.github.novacrypto.bip32.FakeHmacSha512.fakeHmacSha512Responses;
import static io.github.novacrypto.bip32.FakeHmacSha512.toHeadOf64BytesArray;
import static io.github.novacrypto.bip32.Secp256k1SC.n;
import static org.junit.Assert.assertEquals;

/**
 * https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Private_parent_key_rarr_private_child_key
 * <p>
 * In case parse256(IL) ≥ n or ki = 0, the resulting key is invalid, and one should proceed with the next value for i.
 * (Note: this has probability lower than 1 in 2127.)
 * <p>
 * As unlikely as this is, these are the tests. They use jmockit as I don't know of any test vectors for this very
 * improbable scenario.
 */
@RunWith(JMockit.class)
public final class PrivateKeyEdgeCases {

    private void assertKeyIsOfIndex(int requestedIndex, int expectedIndex, BigInteger... il) {
        assertKeyIsOfIndex(requestedIndex, expectedIndex, toHeadOf64BytesArray(il));
    }

    private void assertKeyIsOfIndex(int requestedIndex, int expectedIndex, byte[]... I) {
        PrivateKey privateKey = givenPrivateKey();
        String expected = privateKey.cKDpriv(expectedIndex).extendedBase58();
        fakeHmacSha512Responses(I);
        String actual = privateKey.cKDpriv(requestedIndex).extendedBase58();
        assertEquals(expected, actual);
    }

    @Test
    public void when_parse256_Il_equal_n_returns_next() {
        assertKeyIsOfIndex(0, 1, n());
    }

    @Test
    public void when_parse256_Il_equal_n_returns_next_alternative_indexes() {
        assertKeyIsOfIndex(9, 10, n());
    }

    @Test
    public void when_parse256_Il_greater_n_returns_next_child() {
        assertKeyIsOfIndex(0, 1, n().add(BigInteger.ONE));
    }

    @Test
    public void when_parse256_Il_greater_n_returns_next_child_alternative_indexes() {
        assertKeyIsOfIndex(1000, 1001, n().add(BigInteger.ONE));
    }

    @Test
    public void when_parse256_Il_greater_equal_n_twice_in_row_returns_next_child() {
        assertKeyIsOfIndex(500, 502, n(), n().add(BigInteger.ONE));
    }

    @Test
    public void when_ki_equals_0_returns_next_child() {
        assertKeyIsOfIndex(0, 1,
                new BigInteger("-21730599559909548320659785999896299616815532032911214206397141545081335487970")
                        .toByteArray());
    }

    @Test
    public void when_ki_equals_0_returns_next_child_alternative_indexes() {
        assertKeyIsOfIndex(100, 101,
                new BigInteger("-21730599559909548320659785999896299616815532032911214206397141545081335487970")
                        .toByteArray());
    }

    private static PrivateKey givenPrivateKey() {
        return PrivateKey.fromSeed(new byte[0], Bitcoin.MAIN_NET);
    }
}