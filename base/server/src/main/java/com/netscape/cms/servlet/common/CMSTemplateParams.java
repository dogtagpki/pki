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
package com.netscape.cms.servlet.common;

import java.util.Enumeration;
import java.util.Vector;

import com.netscape.cmscore.base.ArgBlock;

/**
 * Holds template parameters
 *
 * @version $Revision$, $Date$
 */
public class CMSTemplateParams {
    private ArgBlock mHeader;
    private ArgBlock mFixed;
    private Vector<ArgBlock> mRepeat = new Vector<>();

    public CMSTemplateParams() {
    }

    public CMSTemplateParams(ArgBlock header, ArgBlock fixed) {
        mHeader = header;
        mFixed = fixed;
    }

    public void setHeader(ArgBlock h) {
        mHeader = h;
    }

    public ArgBlock getHeader() {
        return mHeader;
    }

    public void setFixed(ArgBlock f) {
        mFixed = f;
    }

    public ArgBlock getFixed() {
        return mFixed;
    }

    public void addRepeatRecord(ArgBlock r) {
        mRepeat.addElement(r);
    }

    public void clearRepeatRecords() {
        mRepeat = new Vector<>();
    }

    public Enumeration<ArgBlock> queryRecords() {
        return mRepeat.elements();
    }
}
