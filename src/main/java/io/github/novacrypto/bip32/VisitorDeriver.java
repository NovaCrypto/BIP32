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

import io.github.novacrypto.bip32.derivation.CharSequenceDerivation;
import io.github.novacrypto.bip32.derivation.Derivation;
import io.github.novacrypto.bip32.derivation.Derive;

final class VisitorDeriver<Node> implements Derive<Node> {

    private final Derivation.Visitor<Node> standardVisitor;
    private final Node rootNode;

    VisitorDeriver(final Derivation.Visitor<Node> standardVisitor, final Node rootNode) {
        this.standardVisitor = standardVisitor;
        this.rootNode = rootNode;
    }

    @Override
    public Node derive(final CharSequence derivationPath) {
        return derive(derivationPath, CharSequenceDerivation.INSTANCE);
    }

    @Override
    public <Path> Node derive(final Path derivationPath, final Derivation<Path> derivation) {
        return derivation.derive(rootNode, derivationPath, standardVisitor);
    }
}