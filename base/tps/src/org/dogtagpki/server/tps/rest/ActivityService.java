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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.tps.rest;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.util.Iterator;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import org.dogtagpki.server.tps.TPSSubsystem;
import org.dogtagpki.server.tps.dbs.ActivityDatabase;
import org.dogtagpki.server.tps.dbs.ActivityRecord;
import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.dbs.IDBVirtualList;
import com.netscape.certsrv.logging.ActivityCollection;
import com.netscape.certsrv.logging.ActivityData;
import com.netscape.certsrv.logging.ActivityResource;
import com.netscape.cms.servlet.base.PKIService;

/**
 * @author Endi S. Dewata
 */
public class ActivityService extends PKIService implements ActivityResource {

    @Context
    private UriInfo uriInfo;

    @Context
    private HttpHeaders headers;

    @Context
    private Request request;

    @Context
    private HttpServletRequest servletRequest;

    public ActivityService() {
        CMS.debug("ActivityService.<init>()");
    }

    public ActivityData createActivityData(ActivityRecord activityRecord) {

        ActivityData activityData = new ActivityData();
        activityData.setID(activityRecord.getId());
        activityData.setTokenID(activityRecord.getTokenID());
        activityData.setUserID(activityRecord.getUserID());
        activityData.setIP(activityRecord.getIP());
        activityData.setOperation(activityRecord.getOperation());
        activityData.setResult(activityRecord.getResult());
        activityData.setMessage(activityRecord.getMessage());
        activityData.setDate(activityRecord.getDate());

        String activityID = activityRecord.getId();
        try {
            activityID = URLEncoder.encode(activityID, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }

        URI uri = uriInfo.getBaseUriBuilder().path(ActivityResource.class).path("{activityID}").build(activityID);
        activityData.setLink(new Link("self", uri));

        return activityData;
    }

    public ActivityRecord createActivityRecord(ActivityData activityData) {

        ActivityRecord activityRecord = new ActivityRecord();
        activityRecord.setId(activityData.getID());
        activityRecord.setTokenID(activityData.getTokenID());
        activityRecord.setUserID(activityData.getUserID());
        activityRecord.setIP(activityData.getIP());
        activityRecord.setOperation(activityData.getOperation());
        activityRecord.setResult(activityData.getResult());
        activityRecord.setMessage(activityData.getMessage());
        activityRecord.setDate(activityData.getDate());

        return activityRecord;
    }

    @Override
    public Response findActivities(String filter, Integer start, Integer size) {

        CMS.debug("ActivityService.findActivities()");

        if (filter != null && filter.length() < MIN_FILTER_LENGTH) {
            throw new BadRequestException("Filter is too short.");
        }

        start = start == null ? 0 : start;
        size = size == null ? DEFAULT_SIZE : size;

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            ActivityDatabase database = subsystem.getActivityDatabase();
            ActivityCollection response = new ActivityCollection();

            if (filter == null) {
                retrieveActivitiesWithVLV(database, start, size, response);
            } else {
                retrieveActivitiesWithoutVLV(database, filter, start, size, response);
            }

            if (start > 0) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", Math.max(start - size, 0)).build();
                response.addLink(new Link("prev", uri));
            }

            if (start + size < response.getTotal()) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", start + size).build();
                response.addLink(new Link("next", uri));
            }

            return createOKResponse(response);

        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException(e.getMessage());
        }
    }

    protected void retrieveActivitiesWithVLV(
            ActivityDatabase database,
            Integer start,
            Integer size,
            ActivityCollection response) throws Exception {

        // search with VLV sorted by date in reverse order
        IDBVirtualList<ActivityRecord> list = database.findRecords(
                null, null, new String[] { "-date" }, size);

        int total = list.getSize();

        // return entries in the requested page
        for (int i = start; i < start + size && i < total; i++) {
            ActivityRecord record = list.getElementAt(i);

            if (record == null) {
                CMS.debug("ActivityService: Activity record not found");
                throw new PKIException("Activity record not found");
            }

            response.addEntry(createActivityData(record));
        }

        response.setTotal(total);
    }

    protected void retrieveActivitiesWithoutVLV(
            ActivityDatabase database,
            String filter,
            Integer start,
            Integer size,
            ActivityCollection response) throws Exception {

        // search without VLV
        Iterator<ActivityRecord> activities = database.findRecords(filter).iterator();

        // TODO: sort results by date in reverse order

        int i = 0;

        // skip to the start of the page
        for (; i < start && activities.hasNext(); i++)
            activities.next();

        // return entries in the requested page
        for (; i < start + size && activities.hasNext(); i++) {
            ActivityRecord record = activities.next();
            response.addEntry(createActivityData(record));
        }

        // count the total entries
        for (; activities.hasNext(); i++) activities.next();
        response.setTotal(i);
    }

    @Override
    public Response getActivity(String activityID) {

        if (activityID == null) throw new BadRequestException("Activity ID is null.");

        CMS.debug("ActivityService.getActivity(\"" + activityID + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            ActivityDatabase database = subsystem.getActivityDatabase();

            return createOKResponse(createActivityData(database.getRecord(activityID)));

        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException(e.getMessage());
        }
    }
}
