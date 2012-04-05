package com.netscape.pkisilent.argparser;

// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

/**
 * Wrapper class which ``holds'' a character value,
 * enabling methods to return character values through
 * arguments.
 */
public class CharHolder implements java.io.Serializable {
    /**
     *
     */
    private static final long serialVersionUID = 7340010668929015745L;
    /**
     * Value of the character, set and examined
     * by the application as needed.
     */
    public char value;

    /**
     * Constructs a new <code>CharHolder</code> with an initial
     * value of 0.
     */
    public CharHolder() {
        value = 0;
    }

    /**
     * Constructs a new <code>CharHolder</code> with a
     * specific initial value.
     *
     * @param c Initial character value.
     */
    public CharHolder(char c) {
        value = c;
    }
}
