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
package com.netscape.cms.servlet.request;

import java.util.Locale;
import java.math.BigInteger;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.servlet.common.CMSTemplateParams;

/**
 * A class representing a request parser.
 * <P>
 *
 * @version $Revision$, $Date$
 */
public class ReqParser implements IReqParser {

    private final static String TYPE = "requestType";
    private final static String STATUS = "status";
    private final static String CREATE_ON = "createdOn";
    private final static String UPDATE_ON = "updatedOn";
    private final static String UPDATE_BY = "updatedBy";

    /**
     * Constructs a request parser.
     */
    public ReqParser() {
    }

    /**
     * Maps request object into argument block.
     */
    public void fillRequestIntoArg(Locale l, IRequest req, CMSTemplateParams argSet, IArgBlock arg)
            throws EBaseException {
        arg.addStringValue(TYPE, req.getRequestType());
        arg.addBigIntegerValue("seqNum",
                new BigInteger(req.getRequestId().toString()), 10);
        arg.addStringValue(STATUS,
                req.getRequestStatus().toString());
        arg.addLongValue(CREATE_ON,
                req.getCreationTime().getTime() / 1000);
        arg.addLongValue(UPDATE_ON,
                req.getModificationTime().getTime() / 1000);
        String updatedBy = req.getExtDataInString(IRequest.UPDATED_BY);

        if (updatedBy == null)
            updatedBy = "";
        arg.addStringValue(UPDATE_BY, updatedBy);

        SessionContext ctx = SessionContext.getContext();
        String id = (String) ctx.get(SessionContext.USER_ID);

        arg.addStringValue("callerName", id);

        String owner = req.getRequestOwner();

        if (owner != null)
            arg.addStringValue("assignedTo", owner);
    }
}
