/*
 *  BIP32 library, a Java implementation of BIP32
 *  Copyright (C) 2017-2018 Alan Evans, NovaCrypto
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

import java.util.Arrays;

final class ByteArrayReader {

    private final byte[] bytes;
    private int idx = 0;

    ByteArrayReader(final byte[] source) {
        this.bytes = source;
    }

    byte[] readRange(final int length) {
        final byte[] range = Arrays.copyOfRange(this.bytes, idx, idx + length);
        idx += length;
        return range;
    }

    /**
     * deserialize a 32-bit unsigned integer i as a 4-byte sequence, most significant byte first.
     */
    int readSer32() {
        int result = read();
        result <<= 8;
        result |= read();
        result <<= 8;
        result |= read();
        result <<= 8;
        result |= read();
        return result;
    }

    int read() {
        return 0xff & bytes[idx++];
    }
}