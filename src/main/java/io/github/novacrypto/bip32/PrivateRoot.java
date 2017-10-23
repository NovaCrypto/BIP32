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
import static io.github.novacrypto.bip32.Sha256.sha256;
import static io.github.novacrypto.toruntime.CheckedExceptionToRuntime.toRuntime;

/**
 * A BIP32 root private key
 */
public final class PrivateRoot {

     static final byte[] bitcoinSeed = getBytes("Bitcoin seed");
    final byte[] bytes;
    final EcPair keyPairData;
    final byte[] chainCode;

    private PrivateRoot(final byte[] bytes, final byte[] keyPairData, final byte[] chainCode) {
        this.bytes = bytes;
        this.keyPairData = new EcPair(keyPairData);
        this.chainCode = chainCode;
    }

    public static PrivateRoot fromSeed(final byte[] seed, final Network network) {
        byte[] hash = hmacSha512(bitcoinSeed, seed);

        final byte[] il = Arrays.copyOf(hash, 32);
        final byte[] ir = new byte[hash.length - 32];
        System.arraycopy(hash, 32, ir, 0, ir.length);

        return new PrivateRoot(calculatePrivateRootKey(network, il, ir, false), il, ir);
    }

    public static PrivateRoot fromSeed2(final byte[] seed, final Network network, final PrivateRoot privateRoot) {
        byte[] hash = hmacSha512(bitcoinSeed, seed);

        final byte[] il = seed;
        final byte[] ir = privateRoot.chainCode;

        return new PrivateRoot(calculatePrivateRootKey(network, il, ir, true), il, ir);
    }

    private static byte[] calculatePrivateRootKey(final Network network, final byte[] il,
                                                  final byte[] ir, final boolean neutered) {
        final int version = neutered ? network.getPublicVersion() : network.getVersion();
        final byte[] privateKey = new byte[82];
        final ByteArrayWriter writer = new ByteArrayWriter(privateKey);
        writer.writeIntBigEndian(version);
        writer.writeByte((byte) 0);  //depth
        writer.writeIntBigEndian(0); //parent fingerprint, 0 for master
        writer.writeIntBigEndian(0); //child no, 0 for master
        writer.writeBytes(ir);
        if (!neutered) {
            writer.writeByte((byte) 0); //
            writer.writeBytes(il);
        } else {
            writer.writeBytes(il);
        }
        final byte[] checksum = sha256(sha256(privateKey, 0, 78));
        writer.writeBytes(checksum, 4);
        return privateKey;
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
        return bytes;
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
        return null;
    }
}