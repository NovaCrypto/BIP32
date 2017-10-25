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

final class HdNode {

    private final Network network;
    private final boolean neutered;
    private final byte[] chainCode;
    private final byte[] key;
    private int depth;
    private final Serializer serializer;

    private HdNode(Builder builder) {
        network = builder.network;
        neutered = builder.neutered;
        key = builder.key;
        chainCode = builder.chainCode;
        serializer = new Serializer.Builder()
                .network(builder.network)
                .neutered(builder.neutered)
                .depth(builder.depth)
                .fingerprint(builder.fingerprint)
                .build();
    }

    byte[] serialize() {
        return serializer.serialize(key, chainCode);
    }

    public byte[] getPoint() {
        return new Secp256k1BC().getPoint(key);
    }

    public byte[] getKey() {
        return key;
    }

    public int fingerPrint() {
        final byte[] point = getPoint();
        final byte[] o = hash160(point);
        return ((o[0] & 0xFF) << 24) |
                ((o[1] & 0xFF) << 16) |
                ((o[2] & 0xFF) << 8) |
                (o[3] & 0xFF);
    }

    public int depth() {
        return 0;
    }

    static class Builder {

        private Network network;
        private boolean neutered;
        private byte[] chainCode;
        private byte[] key;
        private int depth;
        private int fingerprint;

        public Builder network(Network network) {
            this.network = network;
            return this;
        }

        public Builder neutered(boolean neutered) {
            this.neutered = neutered;
            return this;
        }

        public Builder key(byte[] key) {
            this.key = key;
            return this;
        }

        public Builder chainCode(byte[] chainCode) {
            this.chainCode = chainCode;
            return this;
        }

        public Builder depth(int depth) {
            this.depth = depth;
            return this;
        }

        public Builder fingerprint(int fingerprint) {
            this.fingerprint = fingerprint;
            return this;
        }

        public HdNode build() {
            return new HdNode(this);
        }
    }
}
