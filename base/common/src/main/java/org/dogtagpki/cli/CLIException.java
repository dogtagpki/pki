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
// (C) 2017 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.cli;

public class CLIException extends Exception {

    private static final long serialVersionUID = 1L;

    int code = -1;

    public CLIException() {
    }

    public CLIException(int code) {
        this.code = code;
    }

    public CLIException(String message) {
        super(message);
    }

    public CLIException(String message, int code) {
        super(message);
        this.code = code;
    }

    public CLIException(String string, Exception e) {
        super(string, e);
    }

    public int getCode() {
        return code;
    }
}
