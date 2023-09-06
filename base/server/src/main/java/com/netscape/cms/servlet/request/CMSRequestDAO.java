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
// (C) 2011 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.servlet.request;

import java.util.Collection;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.request.CMSRequestInfo;
import com.netscape.certsrv.request.CMSRequestInfos;
import com.netscape.certsrv.request.IRequestVirtualList;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestQueue;
import com.netscape.cmscore.request.RequestRecord;
import com.netscape.cmscore.request.RequestRepository;

/**
 * @author alee
 *
 */

public abstract class CMSRequestDAO {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CMSRequestDAO.class);

    protected RequestRepository requestRepository;
    protected RequestQueue queue;

    private String[] vlvFilters = {
            "(requeststate=*)", "(requesttype=enrollment)",
            "(requesttype=recovery)", "(requeststate=canceled)",
            "(&(requeststate=canceled)(requesttype=enrollment))",
            "(&(requeststate=canceled)(requesttype=recovery))",
            "(requeststate=rejected)",
            "(&(requeststate=rejected)(requesttype=enrollment))",
            "(&(requeststate=rejected)(requesttype=recovery))",
            "(requeststate=complete)",
            "(&(requeststate=complete)(requesttype=enrollment))",
            "(&(requeststate=complete)(requesttype=recovery))"
    };

    public static final String ATTR_SERIALNO = "serialNumber";

    public CMSRequestDAO() {
    }

    /**
     * Finds list of requests matching the specified search filter.
     *
     * If the filter corresponds to a VLV search, then that search is executed and the pageSize
     * and start parameters are used. Otherwise, the maxResults and maxTime parameters are
     * used in the regularly indexed search.
     *
     * @param filter - ldap search filter
     * @param start - start position for VLV search
     * @param pageSize - page size for VLV search
     * @param maxResults - max results to be returned in normal search
     * @param maxTime - max time for normal search
     * @param uriInfo - uri context of request
     * @return collection of key request info
     * @throws EBaseException
     */
    public CMSRequestInfos listCMSRequests(String filter, RequestId start, int pageSize, int maxResults, int maxTime,
            UriInfo uriInfo) throws EBaseException {

        logger.info("CMSRequestDAO: Searching for requests with filter " + filter);

        CMSRequestInfos ret = new CMSRequestInfos();
        int totalSize = 0;
        int current = 0;

        if (isVLVSearch(filter)) {

            logger.debug("CMSRequestDAO: performing VLV search");

            IRequestVirtualList vlvlist = requestRepository.getPagedRequestsByFilter(
                    start,
                    false,
                    filter,
                    pageSize + 1,
                    "requestId");

            totalSize = vlvlist.getSize();
            logger.debug("CMSRequestDAO: total: " + totalSize);
            ret.setTotal(totalSize);

            current = vlvlist.getCurrentIndex();

            int numRecords = (totalSize > (current + pageSize)) ? pageSize :
                    totalSize - current;
            logger.debug("CMSRequestDAO: records (" + numRecords + "):");

            for (int i = 0; i < numRecords; i++) {
                Request request = vlvlist.getElementAt(i);
                logger.debug("- " + request.getRequestId().toHexString());
                ret.addEntry(createCMSRequestInfo(request, uriInfo));
            }

        } else {

            logger.debug("CMSRequestDAO: performing non-VLV search");

            // The non-vlv requests are indexed, but are not paginated.
            // We should think about whether they should be, or if we need to
            // limit the number of results returned.
            Collection<RequestRecord> records = requestRepository.listRequestsByFilter(filter, maxResults, maxTime);

            logger.debug("CMSRequestDAO: records:");
            for (RequestRecord record : records) {
                Request request = record.toRequest();
                logger.debug("- " + request.getRequestId().toHexString());
                ret.addEntry(createCMSRequestInfo(request, uriInfo));
            }
            ret.setTotal(ret.getEntries().size());
        }

        // builder for vlv links
        MultivaluedMap<String, String> params = uriInfo.getQueryParameters();
        UriBuilder builder = uriInfo.getAbsolutePathBuilder();
        if (params.containsKey("requestState")) {
            builder.queryParam("requestState", params.getFirst("requestState"));
        }
        if (params.containsKey("requestType")) {
            builder.queryParam("requestType", params.getFirst("requestType"));
        }
        if (params.containsKey("realm")) {
            builder.queryParam("realm", params.getFirst("realm"));
        }
        builder.queryParam("start", "{start}");
        builder.queryParam("pageSize", "{pageSize}");

        return ret;
    }

    private boolean isVLVSearch(String filter) {
        for (int i = 0; i < vlvFilters.length; i++) {
            if (vlvFilters[i].equalsIgnoreCase(filter)) {
                return true;
            }
        }
        return false;
    }

    protected abstract CMSRequestInfo createCMSRequestInfo(Request request, UriInfo uriInfo);
}

