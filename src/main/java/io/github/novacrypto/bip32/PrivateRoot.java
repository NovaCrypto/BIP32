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

import java.io.UnsupportedEncodingException;
import java.util.Arrays;

import static io.github.novacrypto.bip32.HmacSha512.hmacSha512;
import static io.github.novacrypto.bip32.Sha256.sha256;

/**
 * A BIP32 root private key
 */
public final class PrivateRoot {

    private final byte[] bytes;

    private PrivateRoot(final byte[] bytes) {
        this.bytes = bytes;
    }

    public static PrivateRoot fromSeed(final byte[] seed, final Coin coin) throws UnsupportedEncodingException {
        byte[] byteKey = "Bitcoin seed".getBytes("UTF-8");
        byte[] hash = hmacSha512(byteKey, seed);

        final byte[] il = Arrays.copyOf(hash, 32);
        final byte[] ir = new byte[hash.length - 32];
        System.arraycopy(hash, 32, ir, 0, ir.length);

        return new PrivateRoot(calculatePrivateRootKey(coin, il, ir));
    }

    private static byte[] calculatePrivateRootKey(Coin coin, byte[] il, byte[] ir) {
        final byte[] privateKey = new byte[82];
        final ByteArrayWriter writer = new ByteArrayWriter(privateKey);
        writer.writeIntBigEndian(coin.getVersion());
        writer.writeByte((byte) 0);  //depth
        writer.writeIntBigEndian(0); //parent fingerprint, 0 for master
        writer.writeIntBigEndian(0); //child no, 0 for master
        writer.writeBytes(ir);
        boolean netured = false;
        if (!netured) {
            writer.writeByte((byte) 0); //
            writer.writeBytes(il);
        } else {
            //write
        }

        final byte[] checksum = sha256(sha256(privateKey, 0, 78));
        writer.writeBytes(checksum, 4);
        return privateKey;
    }

    public byte[] toByteArray() {
        return bytes;
    }
}