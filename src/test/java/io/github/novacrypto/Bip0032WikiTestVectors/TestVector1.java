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

package io.github.novacrypto.Bip0032WikiTestVectors;

import io.github.novacrypto.bip32.PrivateKey;
import org.junit.Test;

import static io.github.novacrypto.Bip0032WikiTestVectors.TestVectorHelpers.assertBase58;
import static io.github.novacrypto.Bip0032WikiTestVectors.TestVectorHelpers.createMainNetRootFromSeed;
import static io.github.novacrypto.bip32.PrivateKey.hard;

public final class TestVector1 {

    private final PrivateKey root = createMainNetRootFromSeed("000102030405060708090a0b0c0d0e0f");

    @Test
    public void m_private() {
        assertBase58("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
                root);
    }

    @Test
    public void m_public() {
        assertBase58("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
                root.neuter());
    }

    @Test
    public void chain_m_0h_public() {
        assertBase58("xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
                root
                        .cKDpriv(hard(0))
                        .neuter());
    }

    @Test
    public void chain_m_0h_private() {
        assertBase58("xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
                root
                        .cKDpriv(hard(0)));
    }

    @Test
    public void chain_m_0h_1_public() {
        assertBase58("xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
                root
                        .cKDpriv(hard(0))
                        .cKDpriv(1)
                        .neuter());
    }

    @Test
    public void chain_m_0h_1_private() {
        assertBase58("xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
                root
                        .cKDpriv(hard(0))
                        .cKDpriv(1));
    }

    @Test
    public void chain_m_0h_1_2h_public() {
        assertBase58("xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
                root
                        .cKDpriv(hard(0))
                        .cKDpriv(1)
                        .cKDpriv(hard(2))
                        .neuter());
    }

    @Test
    public void chain_m_0h_1_2h_private() {
        assertBase58("xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
                root
                        .cKDpriv(hard(0))
                        .cKDpriv(1)
                        .cKDpriv(hard(2)));
    }

    @Test
    public void chain_m_0h_1_2h_private_derive() {
        assertBase58("xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
                root.derive("m/0'/1/2'"));
    }

    @Test
    public void chain_m_0h_1_2h_2_public() {
        assertBase58("xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
                root
                        .cKDpriv(hard(0))
                        .cKDpriv(1)
                        .cKDpriv(hard(2))
                        .cKDpriv(2)
                        .neuter());
    }

    @Test
    public void chain_m_0h_1_2h_2_private() {
        assertBase58("xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
                root
                        .cKDpriv(hard(0))
                        .cKDpriv(1)
                        .cKDpriv(hard(2))
                        .cKDpriv(2));
    }

    @Test
    public void chain_m_0h_1_2h_2_private_derive() {
        assertBase58("xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
                root.derive("m/0'/1/2'/2"));
    }

    @Test
    public void chain_m_0h_1_2h_2_1000000000_public() {
        assertBase58("xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
                root
                        .cKDpriv(hard(0))
                        .cKDpriv(1)
                        .cKDpriv(hard(2))
                        .cKDpriv(2)
                        .cKDpriv(1000000000)
                        .neuter());
    }

    @Test
    public void chain_m_0h_1_2h_2_1000000000_private() {
        assertBase58("xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
                root
                        .cKDpriv(hard(0))
                        .cKDpriv(1)
                        .cKDpriv(hard(2))
                        .cKDpriv(2)
                        .cKDpriv(1000000000));
    }

    @Test
    public void chain_m_0h_1_2h_2_1000000000_private_derive() {
        assertBase58("xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
                root.derive("m/0'/1/2'/2/1000000000"));
    }
}