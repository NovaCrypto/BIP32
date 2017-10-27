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

import io.github.novacrypto.toruntime.CheckedExceptionToRuntime;

import java.math.BigInteger;
import java.util.Arrays;

import static io.github.novacrypto.bip32.BigIntegerUtils.parse256;
import static io.github.novacrypto.bip32.BigIntegerUtils.ser256;
import static io.github.novacrypto.bip32.HmacSha512.hmacSha512;
import static io.github.novacrypto.bip32.Secp256k1BC.n;
import static io.github.novacrypto.toruntime.CheckedExceptionToRuntime.toRuntime;

/**
 * A BIP32 private key
 */
public final class PrivateKey implements ToByteArray {

    private static final byte[] BITCOIN_SEED = getBytes("Bitcoin seed");

    private final HdKey hdKey;

    private PrivateKey(final Network network, final BigInteger key, final byte[] chainCode) {
        this(new HdKey.Builder()
                .network(network)
                .neutered(false)
                .key(key)
                .chainCode(chainCode)
                .depth(0)
                .childNumber(0)
                .fingerprint(0)
                .build());
    }

    private PrivateKey(final HdKey hdKey) {
        this.hdKey = hdKey;
    }

    public static PrivateKey fromSeed(final byte[] seed, final Network network) {
        final byte[] hash = hmacSha512(BITCOIN_SEED, seed);

        final byte[] il = head32(hash);
        final byte[] ir = tail32(hash);

        return new PrivateKey(network, parse256(il), ir);
    }

    private static byte[] getBytes(final String seed) {
        return toRuntime(new CheckedExceptionToRuntime.Func<byte[]>() {
            @Override
            public byte[] run() throws Exception {
                return seed.getBytes("UTF-8");
            }
        });
    }

    public byte[] toByteArray() {
        return hdKey.serialize();
    }

    public PrivateKey cKDpriv(final int index) {
        final HdKey parent = this.hdKey;
        final byte[] data = new byte[37];
        final ByteArrayWriter writer = new ByteArrayWriter(data);

        if (hardened(index)) {
            writer.concat((byte) 0);
            writer.concat(ser256(parent.key(), 32));
        } else {
            writer.concat(publicKeyBuffer());
        }
        writer.concatSer32(index);

        final byte[] I = hmacSha512(parent.getChainCode(), data);
        Arrays.fill(data, (byte) 0);

        final byte[] Il = head32(I);
        final byte[] Ir = tail32(I);

        return new PrivateKey(new HdKey.Builder()
                .network(parent.getNetwork())
                .neutered(false)
                .key(parse256(Il).add(parent.key()).mod(n()))
                .chainCode(Ir)
                .depth(parent.depth() + 1)
                .childNumber(index)
                .fingerprint(parent.fingerPrint())
                .build());
    }

    private static byte[] head32(final byte[] bytes) {
        return Arrays.copyOf(bytes, 32);
    }

    private static byte[] tail32(final byte[] bytes) {
        final byte[] result = new byte[bytes.length - 32];
        System.arraycopy(bytes, 32, result, 0, result.length);
        return result;
    }

    private static boolean hardened(final int i) {
        return (i & 0x80000000) != 0;
    }

    private byte[] publicKeyBuffer() {
        return hdKey.point();
    }

    public PublicKey neuter() {
        return PublicKey.from(hdKey);
    }
}