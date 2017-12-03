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

import io.github.novacrypto.bip32.derivation.CkdFunction;
import io.github.novacrypto.bip32.derivation.CkdFunctionDerive;
import io.github.novacrypto.bip32.derivation.Derivation;
import io.github.novacrypto.bip32.derivation.Derive;

import static io.github.novacrypto.base58.Base58.base58Encode;
import static io.github.novacrypto.bip32.BigIntegerUtils.parse256;
import static io.github.novacrypto.bip32.ByteArrayWriter.head32;
import static io.github.novacrypto.bip32.ByteArrayWriter.tail32;
import static io.github.novacrypto.bip32.HmacSha512.hmacSha512;
import static io.github.novacrypto.bip32.Index.isHardened;
import static io.github.novacrypto.bip32.derivation.CkdFunctionResultCacheDecorator.newCacheOf;
import static io.github.novacrypto.hashing.Hash160.hash160into;
import static io.github.novacrypto.hashing.Sha256.sha256Twice;

/**
 * A BIP32 public key
 */
public final class PublicKey implements
        Derive<PublicKey>,
        CKDpub,
        ExtendedKey {

    public static Deserializer<PublicKey> deserializer() {
        return PublicKeyDeserializer.DEFAULT;
    }

    public static Deserializer<PublicKey> deserializer(final Networks networks) {
        return new PublicKeyDeserializer(networks);
    }

    private static final CkdFunction<PublicKey> CKD_FUNCTION = new CkdFunction<PublicKey>() {
        @Override
        public PublicKey deriveChildKey(final PublicKey parent, final int childIndex) {
            return parent.cKDpub(childIndex);
        }
    };

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

    PublicKey(final HdKey hdKey) {
        this.hdKey = hdKey;
    }

    @Override
    public PublicKey cKDpub(final int index) {
        if (isHardened(index))
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
    public byte[] extendedKeyByteArray() {
        return hdKey.serialize();
    }

    @Override
    public String extendedBase58() {
        return base58Encode(extendedKeyByteArray());
    }

    public String p2pkhAddress() {
        return encodeAddress(hdKey.getNetwork().p2pkhVersion(), hdKey.getKey());
    }

    public String p2shAddress() {
        final byte[] script = new byte[22];
        script[1] = (byte) 20;
        hash160into(script, 2, hdKey.getKey());
        return encodeAddress(hdKey.getNetwork().p2shVersion(), script);
    }

    private static String encodeAddress(final byte version, final byte[] data) {
        final byte[] address = new byte[25];
        address[0] = version;
        hash160into(address, 1, data);
        System.arraycopy(sha256Twice(address, 0, 21), 0, address, 21, 4);
        return base58Encode(address);
    }

    public Derive<PublicKey> derive() {
        return derive(CKD_FUNCTION);
    }

    public Derive<PublicKey> deriveWithCache() {
        return derive(newCacheOf(CKD_FUNCTION));
    }

    @Override
    public PublicKey derive(final CharSequence derivationPath) {
        return derive().derive(derivationPath);
    }

    @Override
    public <Path> PublicKey derive(final Path derivationPath, final Derivation<Path> derivation) {
        return derive().derive(derivationPath, derivation);
    }

    private Derive<PublicKey> derive(final CkdFunction<PublicKey> ckdFunction) {
        return new CkdFunctionDerive<>(ckdFunction, this);
    }

    @Override
    public Network network() {
        return hdKey.getNetwork();
    }

    @Override
    public int depth() {
        return hdKey.depth();
    }

    @Override
    public int childNumber() {
        return hdKey.getChildNumber();
    }
}