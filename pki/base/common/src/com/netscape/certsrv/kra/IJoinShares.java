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
package com.netscape.certsrv.kra;

/**
 * Use Java's reflection API to leverage CMS's old Share and JoinShares
 * implementations.
 * 
 * @deprecated
 * @version $Revision$ $Date$
 */
public interface IJoinShares {

    public void initialize(int threshold) throws Exception;

    public void addShare(int shareNum, byte[] share);

    public int getShareCount();

    public byte[] recoverSecret();
}
