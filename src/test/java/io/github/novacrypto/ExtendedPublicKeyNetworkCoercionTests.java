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
import io.github.novacrypto.bip32.ExtendedPublicKey;
import io.github.novacrypto.bip32.networks.Bitcoin;
import io.github.novacrypto.bip32.networks.Litecoin;
import org.junit.Test;

import static io.github.novacrypto.Asserts.assertBase58KeysEqual;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;

public final class ExtendedPublicKeyNetworkCoercionTests {

    @Test
    public void returnSameInstanceIfNetworkMatches() {
        final ExtendedPublicKey pubKey = givenABitcoinPublicKey();
        assertSame(pubKey, pubKey.toNetwork(Bitcoin.MAIN_NET));
    }

    @Test
    public void canSwitchNetwork() {
        final ExtendedPublicKey pubKey = givenABitcoinPublicKey();
        final ExtendedPublicKey actual = pubKey.toNetwork(Bitcoin.TEST_NET);
        assertSame(actual.network(), Bitcoin.TEST_NET);
    }

    @Test
    public void coerceBackAndCheckSerialization() {
        final String xpub = "xpub68UW4NdE5Bii2nfdWiUFZA5BaeyCKpViFfxQbRLehgHAUhZb1CbFmthKphmWQQ2QecqhLdwtbNbFUXhGWCk4EfDRCcVSuoNs71xmzRCkoFz";
        final ExtendedPublicKey pubKey = ExtendedPublicKey.deserializer().deserialize(xpub);
        final ExtendedPublicKey converted = pubKey.toNetwork(Bitcoin.TEST_NET).toNetwork(Bitcoin.MAIN_NET);
        assertNotSame(pubKey, converted);
        assertBase58KeysEqual(xpub, converted.extendedBase58());
    }

    @Test
    public void coerceBackAndCheckSerializationViaExtendedKey() {
        final String xpub = "xpub6D2U48MoKPELMr44cFAwFkTxaatdbRGmXy9LassnvqaEDkSKDBh8CrhPXLp3dHzugP87FJ4TMv4W59SiyzcnFFzm5sFj6z3VwPkzAyFHShk";
        final ExtendedKey pubKey = ExtendedPublicKey.deserializer().deserialize(xpub);
        final ExtendedKey converted = pubKey.toNetwork(Bitcoin.TEST_NET).toNetwork(Bitcoin.MAIN_NET);
        assertNotSame(pubKey, converted);
        assertBase58KeysEqual(xpub, converted.extendedBase58());
    }

    @Test
    public void coerceToOtherNetworkAndCheckSerialization() {
        final String xpub = "xpub69XT5CLAK9vDFmq5pB7QEEPLAWt7bCxhaYzQWwGrW5zLQgxN3WQdDr5Y6WTX3bd2zTFv3zHvEBvHGkTRt4VBpDxYo6vxunzEoXGN5RWbveB";
        final ExtendedPublicKey pubKey = ExtendedPublicKey.deserializer().deserialize(xpub);
        final ExtendedPublicKey converted = pubKey.toNetwork(Litecoin.MAIN_NET);
        assertNotSame(pubKey, converted);
        assertBase58KeysEqual("Ltub2VxZXqYCCbEDW972Qf7Q66VZFKCgLzUqhqCPM21xsaq394bAhWuN3VZyTNyYi12HaffVe7gU5DZfNqpYnxadf9jy6EpRaUkHJ22hywhADZM",
                converted.extendedBase58());
    }

    private ExtendedPublicKey givenABitcoinPublicKey() {
        return ExtendedPublicKey.deserializer().deserialize("xpub6C8zNffsmrupqhz4zdYmFRk43hJAA9PRaDf3NGzgbPUPby8pekUPFr4BTaaY2mt2LgqbyXXACZH8axqsMo14qpHq5LFGhEV3QnpaLqXQHGs");
    }
}