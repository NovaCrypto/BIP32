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

import io.github.novacrypto.bip32.ExtendedPrivateKey;
import org.junit.Test;

import static io.github.novacrypto.Bip0032WikiTestVectors.TestVectorHelpers.assertBase58;
import static io.github.novacrypto.Bip0032WikiTestVectors.TestVectorHelpers.createMainNetRootFromSeed;
import static org.junit.Assert.assertSame;

public final class TestVector1DeriveFromString {

    private final ExtendedPrivateKey root = createMainNetRootFromSeed("000102030405060708090a0b0c0d0e0f");

    @Test
    public void m_private() {
        assertSame(root, root.derive("m"));
    }

    @Test
    public void chain_m_0h_private() {
        assertBase58("xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
                root.derive("m/0'"));
    }

    @Test
    public void chain_m_0h_1_private() {
        assertBase58("xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
                root.derive("m/0'/1"));
    }

    @Test
    public void chain_m_0h_1_2h_private() {
        assertBase58("xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
                root.derive("m/0'/1/2'"));
    }

    @Test
    public void chain_m_0h_1_2h_2_private() {
        assertBase58("xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
                root.derive("m/0'/1/2'/2"));
    }

    @Test
    public void chain_m_0h_1_2h_2_1000000000_private() {
        assertBase58("xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
                root.derive("m/0'/1/2'/2/1000000000"));
    }
}