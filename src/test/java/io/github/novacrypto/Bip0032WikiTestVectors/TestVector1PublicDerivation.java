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

package io.github.novacrypto.Bip0032WikiTestVectors;

import io.github.novacrypto.bip32.IllegalCKDCall;
import io.github.novacrypto.bip32.ExtendedPrivateKey;
import io.github.novacrypto.bip32.ExtendedPublicKey;
import org.junit.Test;

import javax.annotation.CheckReturnValue;

import static io.github.novacrypto.Bip0032WikiTestVectors.TestVectorHelpers.assertBase58;
import static io.github.novacrypto.Bip0032WikiTestVectors.TestVectorHelpers.createMainNetRootFromSeed;
import static io.github.novacrypto.bip32.Index.hard;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public final class TestVector1PublicDerivation {

    private final ExtendedPrivateKey root = createMainNetRootFromSeed("000102030405060708090a0b0c0d0e0f");

    @Test
    public void chain_m_0h_1_2h_2_public() {
        assertBase58("xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
                cKDpubIgnoreResultForSpotBugs(root
                        .cKDpriv(hard(0))
                        .cKDpriv(1)
                        .cKDpub(hard(2)), 2));
    }

    @Test
    public void verified_on_bip32_org() {
        assertBase58("xpub6AvUGrnEpfvJ8L7GLRkBTByQ9uBvUHp9o5VxHrFxhvzV4dSWkySpNaBoLR9FpbnwRmTa69yLHF3QfcaxbWT7gWdwws5k4dpmJvqpEuMWwnj",
                root.derive("m/0/0").neuter());
    }

    @Test
    public void chain_m_0_0() {
        assertBase58(root.derive("m/0/0").neuter(),
                root
                        .cKDpub(0)
                        .cKDpub(0));
    }

    @Test
    public void chain_m_0h_0() {
        assertBase58(root.derive("m/0'/0").neuter(),
                root
                        .cKDpub(hard(0))
                        .cKDpub(0));
    }

    @Test
    public void illegal_chain_m_0h_0h() {
        final ExtendedPublicKey key = root.cKDpub(0);
        final int index = hard(0);
        //noinspection ResultOfMethodCallIgnored
        assertThatThrownBy(() -> cKDpubIgnoreResultForSpotBugs(key, index))
                .isInstanceOf(IllegalCKDCall.class)
                .hasMessage("Cannot derive a hardened key from a public key");
    }

    @CheckReturnValue
    private ExtendedPublicKey cKDpubIgnoreResultForSpotBugs(ExtendedPublicKey key, int index) {
        return key.cKDpub(index);
    }

    @Test
    public void chain_m_0h_1_2h_2_1000000000_public() {
        assertBase58(root.derive("m/0'/1/2'/2/1000000000").neuter(),
                root
                        .cKDpriv(hard(0))
                        .cKDpriv(1)
                        .cKDpub(hard(2))
                        .cKDpub(2)
                        .cKDpub(1000000000));
    }
}