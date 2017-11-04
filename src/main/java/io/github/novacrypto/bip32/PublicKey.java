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

import static io.github.novacrypto.bip32.BigIntegerUtils.parse256;
import static io.github.novacrypto.bip32.ByteArrayWriter.head32;
import static io.github.novacrypto.bip32.ByteArrayWriter.tail32;
import static io.github.novacrypto.bip32.Hash160.hash160;
import static io.github.novacrypto.bip32.HmacSha512.hmacSha512;
import static io.github.novacrypto.bip32.Index.hardened;
import static io.github.novacrypto.bip32.Sha256.sha256Twice;

/**
 * A BIP32 public key
 */
public final class PublicKey implements
        CKDpub,
        ToByteArray {

    static PublicKey from(final HdKey hdKey) {
        return new PublicKey(new HdKey.Builder()
                .network(hdKey.getNetwork())
                .neutered(true)
                .key(hdKey.getPoint())
                .parentFingerprint(hdKey.getParentFingerprint())
                .depth(hdKey.depth())
                .childNumber(hdKey.getChildNumber())
                .chainCode(hdKey.getChainCode())
                .build());
    }

    private final HdKey hdKey;

    private PublicKey(final HdKey hdKey) {
        this.hdKey = hdKey;
    }

    @Override
    public PublicKey cKDpub(final int index) {
        if (hardened(index))
            throw new IllegalCKDCall("Cannot derive a hardened key from a public key");

        final HdKey parent = this.hdKey;
        final byte[] kPar = parent.getKey();

        final byte[] data = new byte[37];
        final ByteArrayWriter writer = new ByteArrayWriter(data);
        writer.concat(kPar, 33);
        writer.concatSer32(index);

        final byte[] I = hmacSha512(parent.getChainCode(), data);
        final byte[] Il = head32(I);
        final byte[] Ir = tail32(I);

        final byte[] key = Secp256k1BC.pointSerP(parse256(Il), kPar);

        return new PublicKey(new HdKey.Builder()
                .network(parent.getNetwork())
                .neutered(true)
                .depth(parent.depth() + 1)
                .parentFingerprint(parent.calculateFingerPrint())
                .key(key)
                .chainCode(Ir)
                .childNumber(index)
                .build());
    }

    @Override
    public byte[] toByteArray() {
        return hdKey.serialize();
    }

    public byte[] p2pkhAddress() {
        return encodeAddress(hdKey.getNetwork().p2pkhVersion(), hdKey.getKey());
    }

    public byte[] p2shAddress() {
        final byte[] script = new byte[22];
        final ByteArrayWriter scriptWriter = new ByteArrayWriter(script);
        scriptWriter.concat((byte) 0);
        scriptWriter.concat((byte) 20);
        scriptWriter.concat(hash160(hdKey.getKey()));
        return encodeAddress(hdKey.getNetwork().p2shVersion(), script);
    }

    private byte[] encodeAddress(final byte version, final byte[] data) {
        final byte[] address = new byte[25];
        final ByteArrayWriter writer = new ByteArrayWriter(address);
        writer.concat(version);
        writer.concat(hash160(data));
        writer.concat(sha256Twice(address, 0, 21), 4);
        return address;
    }
}