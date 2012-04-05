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
package com.netscape.certsrv.logging;

/**
 * A static class to log error messages to the Console
 *
 * @version $Revision$, $Date$
 */
public class ConsoleError {
    private static final ConsoleLog console = new ConsoleLog();

    /**
     * Send the given event to the Console.
     *
     * @param ev log event to be sent to the console
     */
    public static void send(ILogEvent ev) {
        console.log(ev);
        console.flush();
    }

}
