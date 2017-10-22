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
import io.github.novacrypto.bip32.networks.Litecoin;
import io.github.novacrypto.bip39.SeedCalculator;
import org.junit.Test;

import java.math.BigInteger;
import java.util.Arrays;

import static io.github.novacrypto.base58.Base58.base58Decode;
import static io.github.novacrypto.base58.Base58.base58Encode;
import static io.github.novacrypto.bip32.HmacSha512.hmacSha512;
import static org.junit.Assert.assertEquals;

public final class Bip32PublicRootTests {

    @Test
    public void bip32RootBitcoinMainnet() {
        assertBip32Root(
                "xpub661MyMwAqRbcGdEWVXQMcE9zeThTv7X2wXrcSZAo27cZfNEubi1emDrksQppSupTfsNcsu9cyHP7pxEraUrYinxcMjgNLcH4N6Kagd1jrrc",
                "edge talent poet tortoise trumpet dose", Bitcoin.MAIN_NET);
    }

    @Test
    public void bip32RootLitecoinMainnet() {
        assertBip32Root(
                "xpub661MyMwAqRbcGdEWVXQMcE9zeThTv7X2wXrcSZAo27cZfNEubi1emDrksQppSupTfsNcsu9cyHP7pxEraUrYinxcMjgNLcH4N6Kagd1jrrc",
                "edge talent poet tortoise trumpet dose", Litecoin.MAIN_NET);
    }

    @Test
    public void bip32RootBitcoinTestNet() {
        assertBip32Root(
                "tpubD6NzVbkrYhZ4YRRMwiPSp9VMyao7uW26VASuo7DwN2NTQeucfvrjufXb7SubyQmhTmuXVUfVWPDAX8jTyLhncEQuRLRg28wHx3uzSiPBDzL",
                "edge talent poet tortoise trumpet dose", Bitcoin.TEST_NET);
    }

    private void assertBip32Root(String expectedBip32Root, String mnemonic, Network network) {
        final byte[] seed = new SeedCalculator().calculateSeed(mnemonic, "");

        final byte[] bip32Root = findBip32Root(seed, network);
        final String actualBip32Root = base58Encode(bip32Root).toString();
        assertEquals(toHex(base58Decode(expectedBip32Root)), toHex(base58Decode(actualBip32Root)));
    }

    private byte[] findBip32Root(byte[] seed, Network network) {
        final byte[] bytes = PrivateRoot.fromSeed(seed, network)
                .toByteArray();


        final byte[] q = new Secp256k1BC().getPoint(bytes);

        return PrivateRoot.fromSeed(q,network).toByteArray();

//        byte[] result = new byte[82];
//
//        final ByteArrayWriter writer = new ByteArrayWriter(result);
//
//        writer.writeIntBigEndian(network.getVersion());
//        writer.writeByte((byte) 0);  //depth
//        writer.writeIntBigEndian(0); //parent fingerprint, 0 for master
//        writer.writeIntBigEndian(0); //child no, 0 for master
//
//        byte[] hash = hmacSha512(byteKey, seed);
//
//        final byte[] il = Arrays.copyOf(hash, 32);
//        final byte[] ir = new byte[hash.length - 32];
//        System.arraycopy(hash, 32, ir, 0, ir.length);
//
//
//
//        return result;

        //return bytes;
    }

    private static String toHex(byte[] array) {
        final BigInteger bi = new BigInteger(1, array);
        final String hex = bi.toString(16);
        final int paddingLength = (array.length * 2) - hex.length();
        if (paddingLength > 0) {
            return String.format("%0" + paddingLength + "d", 0) + hex;
        } else {
            return hex;
        }
    }
}