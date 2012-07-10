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
 * This interface defines all the prefix tags
 * used in the administration protocol between
 * the console and the server.
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 */
public interface PrefixDef {

    //user and group
    public final static String PX_GROUP = "group";
    public final static String PX_USER = "user";
    public final static String PX_CERT = "cert";
    public final static String PX_SYS = "SYS_";
    public final static String PX_DEF = "DEF_";
    public final static String PX_PP = "CERT_PP";

    //log content
    public final static String PX_LOG = "log";

}
