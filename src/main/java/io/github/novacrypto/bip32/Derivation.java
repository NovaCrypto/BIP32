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

import static io.github.novacrypto.bip32.Index.hard;

final class Derivation<T> {

    interface Visitor<T> {
        T visit(final T parent, final int childIndex);
    }

    private final Visitor<T> visitor;

    Derivation(final Visitor<T> visitor) {
        this.visitor = visitor;
    }

    T derive(final T startAt, final CharSequence derivationPath) {
        final int length = derivationPath.length();
        if (length == 1)
            return startAt;
        T current = startAt;
        int buffer = 0;
        for (int i = 2; i < length; i++) {
            final char c = derivationPath.charAt(i);
            switch (c) {
                case '\'':
                    buffer = hard(buffer);
                    break;
                case '/':
                    current = visitor.visit(current, buffer);
                    buffer = 0;
                    break;
                default:
                    buffer *= 10;
                    buffer += c - '0';
            }
        }
        return visitor.visit(current, buffer);
    }
}