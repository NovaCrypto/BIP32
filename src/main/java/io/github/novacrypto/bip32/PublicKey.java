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

/**
 * A BIP32 public key
 */
public final class PublicKey implements ToByteArray {

    static PublicKey from(final HdKey hdKey) {
        return new PublicKey(new HdKey.Builder()
                .network(hdKey.getNetwork())
                .neutered(true)
                .key(parse256(hdKey.point()))
                .fingerprint(hdKey.getParentFingerprint())
                .depth(hdKey.depth())
                .childNumber(hdKey.getChildNumber())
                .chainCode(hdKey.getChainCode())
                .build());
    }

    private final HdKey hdKey;

    private PublicKey(final HdKey hdKey) {
        this.hdKey = hdKey;
    }

    public byte[] toByteArray() {
        return hdKey.serialize();
    }
}