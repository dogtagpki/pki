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
package com.netscape.cmscore.request;

import com.netscape.certsrv.dbs.IDBObj;
import com.netscape.certsrv.dbs.IDBVirtualList;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestVirtualList;

public class ListEnumeration implements IRequestVirtualList {

    protected RequestQueue queue;
    protected IDBVirtualList<IDBObj> list;

    public ListEnumeration(RequestQueue queue, IDBVirtualList<IDBObj> list) {
        this.queue = queue;
        this.list = list;
    }

    public IRequest getElementAt(int i) {
        RequestRecord record = (RequestRecord) list.getElementAt(i);

        if (record == null) {
            return null;
        }

        return queue.makeRequest(record);
    }

    public int getCurrentIndex() {
        return list.getCurrentIndex();
    }

    public int getSize() {
        return list.getSize();
    }

    public int getSizeBeforeJumpTo() {
        return list.getSizeBeforeJumpTo();
    }

    public int getSizeAfterJumpTo() {
        return list.getSizeAfterJumpTo();
    }
}
