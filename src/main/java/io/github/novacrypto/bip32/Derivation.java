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

import static io.github.novacrypto.bip32.PrivateKey.hard;

final class Derivation<T> {

    interface Visitor<T> {
        T visit(final T parent, final int childIndex);
    }

    private final Visitor<T> visitor;

    Derivation(final Visitor<T> visitor) {
        this.visitor = visitor;
    }

    T derive(final T startAt, final String derivationPath) {
        final String[] split = derivationPath.split("/");
        T current = startAt;
        for (int i = 1; i < split.length; i++)
            current = visitor.visit(current, toIndex(split[i]));
        return current;
    }

    private static int toIndex(final String s) {
        if (s.endsWith("'")) {
            return hard(Integer.parseInt(s.substring(0, s.length() - 1)));
        } else {
            return Integer.parseInt(s);
        }
    }
}