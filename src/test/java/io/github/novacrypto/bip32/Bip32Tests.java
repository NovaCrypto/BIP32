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

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static io.github.novacrypto.base58.Base58.base58Encode;
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
        byte[] hash = hmac(byteKey, seed);

        final byte[] il = Arrays.copyOf(hash, 32);
        final byte[] ir = new byte[hash.length - 32];
        System.arraycopy(hash, 32, ir, 0, ir.length);

        //base58
        byte[] base58 = new byte[82];
        int version = coin.getVersion();
        int idx = 0;
        idx = writeInt(base58, version, idx);
        base58[idx++] = 0; //depth
        idx = writeInt(base58, 0, idx); //parent fingerprint, 0 for master
        idx = writeInt(base58, 0, idx); //child no, 0 for master
        idx = writeBytes(base58, ir, idx);
        boolean netured = false;
        if (!netured) {
            base58[idx++] = 0; //
            idx = writeBytes(base58, il, idx);
        } else {
            //write
        }

        final byte[] checksum = shar256(shar256(base58, 0, 78));
        writeBytes(base58, checksum, idx, 4);
        return base58;
    }

    private static byte[] shar256(byte[] bytes) {
        return shar256(bytes, 0, bytes.length);
    }

    private static byte[] shar256(byte[] bytes, int offset, int length) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(bytes, offset, length);
            return digest.digest();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static int writeBytes(byte[] bytes, byte[] bytesSource, int offset, int length) {
        System.arraycopy(bytesSource, 0, bytes, offset, length);
        return offset + length;
    }

    private static int writeBytes(byte[] bytes, byte[] bytesSource, int offset) {
        return writeBytes(bytes, bytesSource, offset, bytesSource.length);
    }

    private static int writeInt(byte[] bytes, int value, int offset) {
        bytes[offset] = (byte) (value >> 24);
        bytes[offset + 1] = (byte) (value >> 16);
        bytes[offset + 2] = (byte) (value >> 8);
        bytes[offset + 3] = (byte) (value);
        return offset + 4;
    }

    private static byte[] hmac(byte[] byteKey, byte[] seed) throws NoSuchAlgorithmException, InvalidKeyException {
        final String HMAC_SHA256 = "HmacSHA512";
        final Mac sha512_HMAC = Mac.getInstance(HMAC_SHA256);
        final SecretKeySpec keySpec = new SecretKeySpec(byteKey, HMAC_SHA256);
        sha512_HMAC.init(keySpec);
        return sha512_HMAC.doFinal(seed);
    }
}
