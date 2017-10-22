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

import static io.github.novacrypto.bip32.Hash160.hash160;
import static io.github.novacrypto.bip32.Secp256k1BC.point;

final class HdKey {

    private final Network network;
    private final byte[] chainCode;
    private final byte[] key;
    private final Serializer serializer;
    private final int parentFingerprint;
    private final int childNumber;
    private final int depth;

    private HdKey(final Builder builder) {
        network = builder.network;
        key = builder.key;
        parentFingerprint = builder.fingerprint;
        childNumber = builder.childNumber;
        chainCode = builder.chainCode;
        depth = builder.depth;
        serializer = new Serializer.Builder()
                .network(builder.network)
                .neutered(builder.neutered)
                .depth(builder.depth)
                .childNumber(builder.childNumber)
                .fingerprint(builder.fingerprint)
                .build();
    }

    byte[] serialize() {
        return serializer.serialize(key, chainCode);
    }

    byte[] getPoint() {
        return point(key);
    }

    byte[] getKey() {
        return key;
    }

    int getParentFingerprint() {
        return parentFingerprint;
    }

    int fingerPrint() {
        final byte[] point = getPoint();
        final byte[] o = hash160(point);
        return ((o[0] & 0xFF) << 24) |
                ((o[1] & 0xFF) << 16) |
                ((o[2] & 0xFF) << 8) |
                (o[3] & 0xFF);
    }

    int depth() {
        return depth;
    }

    public Network getNetwork() {
        return network;
    }

    byte[] getChainCode() {
        return chainCode;
    }

    int getChildNumber() {
        return childNumber;
    }

    static class Builder {

        private Network network;
        private boolean neutered;
        private byte[] chainCode;
        private byte[] key;
        private int depth;
        private int childNumber;
        private int fingerprint;

        Builder network(final Network network) {
            this.network = network;
            return this;
        }

        Builder neutered(final boolean neutered) {
            this.neutered = neutered;
            return this;
        }

        Builder key(final byte[] key) {
            this.key = key;
            return this;
        }

        Builder chainCode(final byte[] chainCode) {
            this.chainCode = chainCode;
            return this;
        }

        Builder depth(final int depth) {
            this.depth = depth;
            return this;
        }

        Builder childNumber(final int childNumber) {
            this.childNumber = childNumber;
            return this;
        }

        Builder fingerprint(final int fingerprint) {
            this.fingerprint = fingerprint;
            return this;
        }

        HdKey build() {
            return new HdKey(this);
        }
    }
}
