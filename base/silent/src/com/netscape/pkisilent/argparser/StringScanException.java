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

import java.io.IOException;

/**
 * Exception class used by <code>StringScanner</code> when
 * command line arguments do not parse correctly.
 *
 * @author John E. Lloyd, Winter 2001
 * @see StringScanner
 */
class StringScanException extends IOException {
    /**
     *
     */
    private static final long serialVersionUID = 4923445904507805754L;
    int failIdx;

    /**
     * Creates a new StringScanException with the given message.
     *
     * @param msg Error message
     * @see StringScanner
     */

    public StringScanException(String msg) {
        super(msg);
    }

    public StringScanException(int idx, String msg) {
        super(msg);
        failIdx = idx;
    }

    public int getFailIndex() {
        return failIdx;
    }
}
