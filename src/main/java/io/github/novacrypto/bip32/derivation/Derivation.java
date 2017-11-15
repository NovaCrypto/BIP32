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

package io.github.novacrypto.bip32.derivation;

public interface Derivation<Path> {

    interface Visitor<T> {
        /**
         * Finds the child at the given index on the parent.
         *
         * @param parent     The parent to find the child of
         * @param childIndex The index of the child
         * @return the {@link T} for the child
         */
        T visit(final T parent, final int childIndex);
    }

    /**
     * Traverse the nodes from the root to find the node referenced by the path.
     *
     * @param root The root of the path
     * @param path    The path to follow
     * @param visitor Allows you to follow one link
     * @param <Node>  The type of node we are visiting
     * @return The final node found at the end of the path
     */
    <Node> Node derive(final Node root, final Path path, final Visitor<Node> visitor);
}