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
import io.github.novacrypto.bip32.PublicKey;
import io.github.novacrypto.bip32.networks.Bitcoin;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.util.Arrays;
import java.util.Collection;

import static io.github.novacrypto.Asserts.assertBase58AddressEqual;
import static io.github.novacrypto.Asserts.assertBase58KeysEqual;

@RunWith(Parameterized.class)
public final class DeserializeKeysTests {

    private final PrivateKey privateKey;
    private final String privateKeyBase58;

    private final PublicKey publicKey;
    private final String publicKeyBase58;

    @Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
                {"m", Bitcoin.MAIN_NET},
                {"m/1", Bitcoin.MAIN_NET},
                {"m/" + 0x7f6e5d4c, Bitcoin.MAIN_NET},
                {"m/" + 0x7fffffff, Bitcoin.MAIN_NET},
                {"m/" + 0x7fffffff + "'", Bitcoin.MAIN_NET},
                {"m/44'/0'/0'", Bitcoin.MAIN_NET},
                {"m", Bitcoin.TEST_NET},
        });
    }

    public DeserializeKeysTests(CharSequence path, Network network) {
        PrivateKey root = PrivateKey.fromSeed(new byte[0], network);
        privateKey = root.derive(path);
        publicKey = privateKey.neuter();
        privateKeyBase58 = privateKey.extendedBase58();
        publicKeyBase58 = publicKey.extendedBase58();
    }

    @Test
    public void canDeserializePrivate() {
        PrivateKey actual = PrivateKey.deserialize(privateKeyBase58);
        assertBase58KeysEqual(privateKeyBase58, actual.extendedBase58());
    }

    @Test
    public void canDeserializePrivateAndProduceAddresses() {
        PublicKey actual = PrivateKey.deserialize(privateKeyBase58).neuter();
        assertBase58AddressEqual(publicKey.p2pkhAddress(), actual.p2pkhAddress());
        assertBase58AddressEqual(publicKey.p2shAddress(), actual.p2shAddress());
    }

    @Test
    public void canDeserializePublic() {
        PublicKey actual = PublicKey.deserialize(publicKeyBase58);
        assertBase58KeysEqual(publicKeyBase58, actual.extendedBase58());
    }

    @Test
    public void canDeserializePublicAndProduceAddresses() {
        PublicKey actual = PublicKey.deserialize(publicKeyBase58);
        assertBase58AddressEqual(publicKey.p2pkhAddress(), actual.p2pkhAddress());
        assertBase58AddressEqual(publicKey.p2shAddress(), actual.p2shAddress());
    }
}