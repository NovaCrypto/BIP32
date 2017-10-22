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

import org.spongycastle.crypto.digests.RIPEMD160Digest;

import static io.github.novacrypto.bip32.Sha256.sha256;

final class Hash160 {

    static byte[] hash160(final byte[] bytes) {
        return ripemd160(sha256(bytes));
    }

    private static byte[] ripemd160(final byte[] bytes) {
        final RIPEMD160Digest digest = new RIPEMD160Digest();
        digest.update(bytes, 0, bytes.length);
        final byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);
        return output;
    }
}