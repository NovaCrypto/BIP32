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
import io.github.novacrypto.bip32.ExtendedPrivateKey;
import io.github.novacrypto.bip32.networks.Bitcoin;
import io.github.novacrypto.bip32.networks.Litecoin;
import org.junit.Test;

import static io.github.novacrypto.Asserts.assertBase58KeysEqual;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;

public final class ExtendedPrivateKeyNetworkCoercionTests {

    @Test
    public void returnSameInstanceIfNetworkMatches() {
        final ExtendedPrivateKey pubKey = givenABitcoinPrivateKey();
        assertSame(pubKey, pubKey.toNetwork(Bitcoin.MAIN_NET));
    }

    @Test
    public void canSwitchNetwork() {
        final ExtendedPrivateKey pubKey = givenABitcoinPrivateKey();
        final ExtendedPrivateKey actual = pubKey.toNetwork(Bitcoin.TEST_NET);
        assertSame(actual.network(), Bitcoin.TEST_NET);
    }

    @Test
    public void coerceBackAndCheckSerialization() {
        final String xpub = "xprv9uV9es6LEpAQpJbAQgwFC28T2d8hvMmrtT2oo2w39LkBbuESTfH1E6NqyShMVoUqkGW6gqYZGBBuA5i9oSLEiVNTZL9HTqee2ddm4LnQLVP";
        final ExtendedPrivateKey pubKey = ExtendedPrivateKey.deserializer().deserialize(xpub);
        final ExtendedPrivateKey converted = pubKey.toNetwork(Bitcoin.TEST_NET).toNetwork(Bitcoin.MAIN_NET);
        assertNotSame(pubKey, converted);
        assertBase58KeysEqual(xpub, converted.extendedBase58());
    }

    @Test
    public void coerceBackAndCheckSerializationViaExtendedKey() {
        final String xpub = "xprv9uVVwZxyexRUJfusouB1CcDw8RWMDfzVYm4dk5itGWshpVA2CjqQKF11oyoML33sZ4YpUwBTu8YNeawsPF3ctX6DuPmjSDt1rqAcUYVptHR";
        final ExtendedKey pubKey = ExtendedPrivateKey.deserializer().deserialize(xpub);
        final ExtendedKey converted = pubKey.toNetwork(Bitcoin.TEST_NET).toNetwork(Bitcoin.MAIN_NET);
        assertNotSame(pubKey, converted);
        assertBase58KeysEqual(xpub, converted.extendedBase58());
    }

    @Test
    public void coerceToOtherNetworkAndCheckSerialization() {
        final String xpub = "xprv9vY6fgoGUnMv3Hkci9aPs6SbcV3dBkErDL4oiYsEwkTMXtdDVy6Ng3m4FFWjjLVkrQ8ZcDnCsQZuVbyXbHDVzbG9aMK5oD7kUM76SpiNxuT";
        final ExtendedPrivateKey pubKey = ExtendedPrivateKey.deserializer().deserialize(xpub);
        final ExtendedPrivateKey converted = pubKey.toNetwork(Litecoin.MAIN_NET);
        assertNotSame(pubKey, converted);
        assertBase58KeysEqual("Ltpv74nDw47exShFtGQCA3d21WfLokWVGjvBdK6Mg3FfwQ3SYhQ6Nbrw2tTiD23kc48wmWhqgjRj2VGZV76bzQCUdhdVXvGG7AAnGjizWFc1cic",
                converted.extendedBase58());
    }

    private ExtendedPrivateKey givenABitcoinPrivateKey() {
        return ExtendedPrivateKey.deserializer().deserialize("xprv9y9dyA8ywVMXdDubtc1ktHoKVfTfkgfaCzjSZtb533wQjAog7DA8i3jhcHSAazHcaS64LdSgyuzk2qLtjnFs1e6mkz4PKVuiBevUMJ6pRsx");
    }
}