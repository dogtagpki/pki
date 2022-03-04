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
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;

public class RequestListByStatus implements IRequestList {

    protected RequestStatus mStatus;
    protected RequestRepository requestRepository;
    protected ARequestQueue mQueue;
    protected Enumeration<RequestId> mEnumeration;
    protected RequestId mNext;

    @Override
    public boolean hasMoreElements() {
        return (mNext != null);
    }

    @Override
    public Object nextRequest() {
        return null;
    }

    @Override
    public Request nextRequestObject() {
        return null;
    }

    @Override
    public RequestId nextElement() {
        RequestId next = mNext;

        update();

        return next;
    }

    @Override
    public RequestId nextRequestId() {
        RequestId next = mNext;

        update();

        return next;
    }

    public RequestListByStatus(
            Enumeration<RequestId> e,
            RequestStatus s,
            RequestRepository requestRepository,
            ARequestQueue q) {

        mEnumeration = e;
        mStatus = s;
        this.requestRepository = requestRepository;
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
                Request r = requestRepository.readRequest(rId);

                if (r.getRequestStatus() == mStatus)
                    mNext = rId;

                mQueue.releaseRequest(r);
            } catch (Exception e) {
            }
        }
    }
}
