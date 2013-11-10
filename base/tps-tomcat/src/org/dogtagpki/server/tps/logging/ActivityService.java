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

package org.dogtagpki.server.tps.logging;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.util.Iterator;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.UriInfo;

import org.dogtagpki.server.tps.TPSSubsystem;
import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.PKIException;
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

    public final static int DEFAULT_SIZE = 20;

    public ActivityService() {
        CMS.debug("ActivityService.<init>()");
    }

    public ActivityData createActivityData(ActivityRecord activityRecord) {

        ActivityData activityData = new ActivityData();
        activityData.setID(activityRecord.getId());
        activityData.setTokenID(activityRecord.getTokenID());
        activityData.setUserID(activityRecord.getUserID());
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
        activityRecord.setDate(activityData.getDate());

        return activityRecord;
    }

    @Override
    public ActivityCollection findActivities(Integer start, Integer size) {

        CMS.debug("ActivityService.findActivities()");

        try {
            start = start == null ? 0 : start;
            size = size == null ? DEFAULT_SIZE : size;

            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            ActivityDatabase database = subsystem.getActivityDatabase();

            Iterator<ActivityRecord> activities = database.getRecords().iterator();

            ActivityCollection response = new ActivityCollection();
            int i = 0;

            // skip to the start of the page
            for ( ; i<start && activities.hasNext(); i++) activities.next();

            // return entries up to the page size
            for ( ; i<start+size && activities.hasNext(); i++) {
                response.addEntry(createActivityData(activities.next()));
            }

            // count the total entries
            for ( ; activities.hasNext(); i++) activities.next();
            response.setTotal(i);

            if (start > 0) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", Math.max(start-size, 0)).build();
                response.addLink(new Link("prev", uri));
            }

            if (start+size < i) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", start+size).build();
                response.addLink(new Link("next", uri));
            }

            return response;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public ActivityData getActivity(String activityID) {

        if (activityID == null) throw new BadRequestException("Activity ID is null.");

        CMS.debug("ActivityService.getActivity(\"" + activityID + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            ActivityDatabase database = subsystem.getActivityDatabase();

            return createActivityData(database.getRecord(activityID));

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }
}
