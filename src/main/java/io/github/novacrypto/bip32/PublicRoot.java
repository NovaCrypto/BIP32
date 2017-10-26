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

/**
 * A BIP32 root public key
 */
public final class PublicRoot {

    private final HdNode hdNode;

    private PublicRoot(final Network network, final byte[] key, final byte[] chainCode) {
        this(new HdNode.Builder()
                .network(network)
                .neutered(true)
                .key(key)
                .chainCode(chainCode)
                .build());
    }

    public PublicRoot(HdNode hdNode) {
        this.hdNode = hdNode;
    }

    public static PublicRoot fromKey(final Network network, final byte[] key, final byte[] chainCode) {
        return new PublicRoot(network, key, chainCode);
    }

    public byte[] toByteArray() {
        return hdNode.serialize();
    }

    public static PublicRoot from(HdNode hdNode) {
        return new PublicRoot(new HdNode.Builder()
                .network(hdNode.getNetwork())
                .neutered(true)
                .key(hdNode.getPoint())
                .fingerprint(hdNode.getParentFingerprint())
                .depth(hdNode.depth())
                .childNumber(hdNode.getChildNumber())
                .chainCode(hdNode.getChainCode())
                .build());
    }
}