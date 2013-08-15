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
package com.netscape.cmscore.dbs;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.IDBVirtualList;
import com.netscape.certsrv.dbs.IElementProcessor;

/**
 * A default stub ojbect for tests to extend.
 * This class helps test avoid the problem of test stubs having to
 * implement a new stub method every time the interface changes.
 * It also makes the tests clearer by not cluttered them with empty methods.
 *
 * Do not put any behaviour in this class.
 */
public class DBVirtualListDefaultStub<T> implements IDBVirtualList<T> {

    public void setPageSize(int size) {
    }

    public void setSortKey(String sortKey) throws EBaseException {
    }

    public void setSortKey(String[] sortKeys) throws EBaseException {
    }

    public int getSize() {
        return 0;
    }

    public int getSizeBeforeJumpTo() {
        return 0;
    }

    public int getSizeAfterJumpTo() {
        return 0;
    }

    public int getCurrentIndex() {
        return 0;
    }

    public boolean getPage(int first) {
        return false;
    }

    public boolean getPage(String text) {
        return false;
    }

    public T getElementAt(int index) {
        return null;
    }

    public T getJumpToElementAt(int i) {
        return null;
    }

    public void processElements(int startidx, int endidx, IElementProcessor ep)
            throws EBaseException {
    }

    public int getSelectedIndex() {
        return 0;
    }

    public int getFirstIndex() {
        return 0;
    }

}
