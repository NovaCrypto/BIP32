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

import io.github.novacrypto.bip32.networks.DefaultNetworks;

import static io.github.novacrypto.base58.Base58.base58Decode;

final class PrivateKeyDeserializer implements Deserializer<PrivateKey> {

    static final PrivateKeyDeserializer DEFAULT = new PrivateKeyDeserializer(DefaultNetworks.INSTANCE);

    private final Networks networks;

    PrivateKeyDeserializer(final Networks networks) {
        this.networks = networks;
    }

    @Override
    public PrivateKey deserialize(final CharSequence extendedBase58) {
        return deserialize(base58Decode(extendedBase58));
    }

    @Override
    public PrivateKey deserialize(final byte[] extendedBase58) {
        final ByteArrayReader reader = new ByteArrayReader(extendedBase58);
        return new PrivateKey(new HdKey
                .Builder()
                .network(networks.findByPrivateVersion(reader.readSer32()))
                .depth(reader.read())
                .parentFingerprint(reader.readSer32())
                .childNumber(reader.readSer32())
                .chainCode(reader.readRange(32))
                .key(reader.readRange(33))
                .neutered(false)
                .build()
        );
    }
}