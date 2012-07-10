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
package com.netscape.certsrv.common;

/**
 * This interface defines all the administration operations
 * used in the administration protocol between the console
 * and the server.
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 */
public interface OpDef {

    public final static String OP_ADD = "OP_ADD";
    public final static String OP_DELETE = "OP_DELETE";
    public final static String OP_MODIFY = "OP_MODIFY";
    public final static String OP_READ = "OP_READ";
    public final static String OP_SEARCH = "OP_SEARCH";
    public final static String OP_AUTH = "OP_AUTH";
    public final static String OP_JOBS = "OP_JOBS";
    public final static String OP_PROCESS = "OP_PROCESS";
    public final static String OP_VALIDATE = "OP_VALIDATE";
}
