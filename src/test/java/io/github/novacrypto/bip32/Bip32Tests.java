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

import io.github.novacrypto.bip32.coins.Bitcoin;
import io.github.novacrypto.bip32.coins.Litecoin;
import io.github.novacrypto.bip39.SeedCalculator;
import org.junit.Test;

import java.util.Arrays;

import static io.github.novacrypto.base58.Base58.base58Encode;
import static io.github.novacrypto.hash.HmacSha512.hmacSha512;
import static io.github.novacrypto.hash.Sha256.sha256;
import static org.junit.Assert.assertEquals;

public final class Bip32Tests {

    @Test
    public void bip32Root() throws Exception {
        assertBip32Root(
                "xprv9s21ZrQH143K49A3PVsMF6DG6RryWeoBaJw1eAmBTn5anZum4AhQDRYH29DMvQ6BY8HWc1jB4vxWPVoD6mmCcN3L3Wf3fq5pQCAA4suatkG",
                "edge talent poet tortoise trumpet dose", Bitcoin.INSTANCE);
    }

    @Test
    public void bip32RootLiteCoin() throws Exception {
        assertBip32Root(
                "xprv9s21ZrQH143K49A3PVsMF6DG6RryWeoBaJw1eAmBTn5anZum4AhQDRYH29DMvQ6BY8HWc1jB4vxWPVoD6mmCcN3L3Wf3fq5pQCAA4suatkG",
                "edge talent poet tortoise trumpet dose", Litecoin.INSTANCE);
    }

    @Test
    public void bip32RootBitcoinTestNet() throws Exception {
        assertBip32Root(
                "tprv8ZgxMBicQKsPexPa44irQjqFQZHBkAqBurr8WbBdwka4aAer3Y39jAuiwKP1vmUVuZpHc7LwEHYJrMLxDz79RRJva9sMLBosKHuaWYn66oB",
                "edge talent poet tortoise trumpet dose", Bitcoin.TESTNET);
    }

    private void assertBip32Root(String expectedBip32Root, String mnemonic, Coin coin) throws Exception {
        final byte[] seed = new SeedCalculator().calculateSeed(mnemonic, "");

        final byte[] bip32Root = findBip32Root(seed, coin);
        final String actualBip32Root = base58Encode(bip32Root).toString();
        assertEquals(expectedBip32Root, actualBip32Root);
    }

    private byte[] findBip32Root(byte[] seed, Coin coin) throws Exception {
        byte[] byteKey = "Bitcoin seed".getBytes("UTF-8");
        byte[] hash = hmacSha512(byteKey, seed);

        final byte[] il = Arrays.copyOf(hash, 32);
        final byte[] ir = new byte[hash.length - 32];
        System.arraycopy(hash, 32, ir, 0, ir.length);

        //base58
        byte[] base58 = new byte[82];
        ByteArrayWriter writer = new ByteArrayWriter(base58);
        int version = coin.getVersion();
        writer.writeInt(version);
        writer.writeByte((byte) 0);  //depth
        writer.writeInt(0); //parent fingerprint, 0 for master
        writer.writeInt(0); //child no, 0 for master
        writer.writeBytes(ir);
        boolean netured = false;
        if (!netured) {
            writer.writeByte((byte) 0); //
            writer.writeBytes(il);
        } else {
            //write
        }

        final byte[] checksum = sha256(sha256(base58, 0, 78));
        writer.writeBytes(checksum, 4);
        return base58;
    }
}
