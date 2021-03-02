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

import java.util.Enumeration;

import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestList;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;

public class RequestListByStatus implements IRequestList {

    protected RequestStatus mStatus;
    protected IRequestQueue mQueue;
    protected Enumeration<RequestId> mEnumeration;
    protected RequestId mNext;

    public boolean hasMoreElements() {
        return (mNext != null);
    }

    public Object nextRequest() {
        return null;
    }

    public IRequest nextRequestObject() {
        return null;
    }

    public RequestId nextElement() {
        RequestId next = mNext;

        update();

        return next;
    }

    public RequestId nextRequestId() {
        RequestId next = mNext;

        update();

        return next;
    }

    public RequestListByStatus(Enumeration<RequestId> e, RequestStatus s, IRequestQueue q) {
        mEnumeration = e;
        mStatus = s;
        mQueue = q;

        update();
    }

    protected void update() {
        RequestId rId;

        mNext = null;

        while (mNext == null) {
            if (!mEnumeration.hasMoreElements())
                break;

            rId = mEnumeration.nextElement();

            try {
                IRequest r = mQueue.findRequest(rId);

                if (r.getRequestStatus() == mStatus)
                    mNext = rId;

                mQueue.releaseRequest(r);
            } catch (Exception e) {
            }
        }
    }
}
