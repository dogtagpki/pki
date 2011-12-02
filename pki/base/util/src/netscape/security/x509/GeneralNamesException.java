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
package netscape.security.x509;

import java.security.GeneralSecurityException;

/**
 * Generic General Names Exception.
 *
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.4
 */
public class GeneralNamesException extends GeneralSecurityException {
    /**
     *
     */
    private static final long serialVersionUID = -8320001725384815795L;

    /**
     * Constructs a GeneralNamesException with no detail message.
     */
    public GeneralNamesException() {
        super();
    }

    /**
     * Constructs the exception with the specified error message.
     *
     * @param message the requisite error message.
     */
    public GeneralNamesException(String message) {
        super(message);
    }
}
