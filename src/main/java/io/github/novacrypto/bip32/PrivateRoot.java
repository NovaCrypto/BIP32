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

import java.util.Arrays;

import static io.github.novacrypto.bip32.HmacSha512.hmacSha512;
import static io.github.novacrypto.toruntime.CheckedExceptionToRuntime.toRuntime;

/**
 * A BIP32 root private key
 */
public final class PrivateRoot {

    private static final byte[] BITCOIN_SEED = getBytes("Bitcoin seed");

    private final HdNode hdNode;
    private final Network network;
    private final byte[] chainCode;

    private PrivateRoot(final Network network, final byte[] key, final byte[] chainCode) {
        this.network = network;
        this.chainCode = chainCode;
        hdNode = new HdNode.Builder()
                .network(network)
                .neutered(false)
                .key(key)
                .chainCode(chainCode)
                .build();
    }

    public static PrivateRoot fromSeed(final byte[] seed, final Network network) {
        byte[] hash = hmacSha512(BITCOIN_SEED, seed);

        final byte[] il = Arrays.copyOf(hash, 32);
        final byte[] ir = new byte[hash.length - 32];
        System.arraycopy(hash, 32, ir, 0, ir.length);

        return new PrivateRoot(network, il, ir);
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
        return hdNode.serialize();
    }

    public PrivateRoot cKDpriv(int i) {

        byte[] data = new byte[37];
        ByteArrayWriter writer = new ByteArrayWriter(data);
        writer.writeBytes(publicKeyBuffer());
        writer.writeIntBigEndian(i);

        byte[] hash = hmacSha512(chainCode, data);

        final byte[] il = Arrays.copyOf(hash, 32);
        final byte[] ir = new byte[hash.length - 32];
        System.arraycopy(hash, 32, ir, 0, ir.length);

        //let I = HMAC-SHA512(Key = cpar, Data = serP(point(kpar)) || ser32(i)).
        return null;
    }

    private byte[] publicKeyBuffer() {
        return new byte[0];
    }

    public PublicRoot neuter() {
        return PublicRoot.fromKey(network, hdNode.getPoint(), chainCode);
    }
}