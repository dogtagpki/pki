//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.rest.v2;

import java.io.PrintWriter;
import java.util.Date;
import java.util.List;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.dogtagpki.server.tps.TPSEngine;
import org.dogtagpki.server.tps.TPSSubsystem;
import org.dogtagpki.server.tps.dbs.ActivityDatabase;
import org.dogtagpki.server.tps.dbs.ActivityRecord;
import org.dogtagpki.server.tps.dbs.TokenDatabase;
import org.dogtagpki.server.tps.dbs.TokenRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.base.UnauthorizedException;
import com.netscape.certsrv.logging.ActivityCollection;
import com.netscape.certsrv.logging.ActivityData;
import com.netscape.certsrv.user.UserResource;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "activity",
        urlPatterns = "/v2/activities/*")
public class ActivityServlet extends TPSServlet {
    private static final long serialVersionUID = 1L;
    private static final Logger logger = LoggerFactory.getLogger(ActivityServlet.class);

    @Override
    public void get(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String method = "ActivityServlet.get:";
        HttpSession session = request.getSession();
        logger.debug("ActivityServlet.get(): session: {}", session.getId());
        TPSSubsystem subsystem = getTPSSubsystem();
        ActivityDatabase database = subsystem.getActivityDatabase();
        PrintWriter out = response.getWriter();
        List<String> authorizedProfiles = getAuthorizedProfiles(request);
        if (authorizedProfiles.isEmpty()) {
            throw new UnauthorizedException("User not authorized");
        }

        logger.debug("{} pathInfo (\"{}\")", method, request.getPathInfo());
        if(request.getPathInfo() != null) {
            String id = request.getPathInfo().substring(1);
            if(id.isBlank()) {
                throw new BadRequestException("Id is empty");
            }
            logger.debug("{} (\"{}\")", method, id);
            ActivityRecord aRec = null;
            try {
                aRec = database.getRecord(id);
            } catch (Exception e) {
                logger.debug(method +" error retrieving the activity record", e);
                throw new ResourceNotFoundException("Record " + id + " not found");
            }
            if (aRec == null) {
                logger.debug("{} record not found", method);
                throw new ResourceNotFoundException("Record " + id + " not found");
            }
            String type = aRec.getType();

            if ((type != null) && !type.isEmpty() && !authorizedProfiles.contains(UserResource.ALL_PROFILES) && !authorizedProfiles.contains(type)) {
                String msg = "token type restricted: " + type;
                logger.debug("{} {}", method, msg);
                throw new PKIException(msg);
            }
            ActivityData data = createActivityData(aRec);
            out.println(data.toJSON());
            return;
        }
        String filter = request.getParameter("filter");
        if (filter != null && filter.length() < MIN_FILTER_LENGTH) {
            throw new BadRequestException("Filter is too short.");
        }
        int size = request.getParameter("size") == null ?
                DEFAULT_SIZE : Integer.parseInt(request.getParameter("size"));
        int start = request.getParameter("start") == null ? 0 : Integer.parseInt(request.getParameter("start"));

        ActivityCollection activities = retrieveActivities(database, authorizedProfiles, filter, start, size);
        out.println(activities.toJSON());
    }

    private ActivityData createActivityData(ActivityRecord activityRecord) {
        ActivityData activityData = new ActivityData();
        activityData.setID(activityRecord.getId());
        activityData.setTokenID(activityRecord.getTokenID());
        activityData.setUserID(activityRecord.getUserID());
        activityData.setIP(activityRecord.getIP());
        activityData.setOperation(activityRecord.getOperation());
        activityData.setResult(activityRecord.getResult());
        activityData.setMessage(activityRecord.getMessage());
        activityData.setDate(activityRecord.getDate());

        return activityData;
    }
    /**
     * Create data for restricted activity record/
     *
     * Restricted records are records not permitted to be accessed
     * by the user per profile restrictions;  They are shown
     * on display when searched
     */
    public ActivityData createRestrictedActivityData() {

        ActivityData activityData = new ActivityData();
        activityData.setID("<restricted>");
        activityData.setTokenID("<restricted>");
        activityData.setUserID("<restricted>");
        activityData.setIP("<restricted>");
        activityData.setOperation("<restricted>");
        activityData.setResult("<restricted>");
        activityData.setMessage("<restricted>");
        activityData.setDate(new Date(0L));

        return activityData;
    }

    private ActivityCollection retrieveActivities(
            ActivityDatabase database,
            List<String> authorizedProfiles,
            String filter,
            int start,
            int size) throws Exception {

        String method = "ActivityServlet.retrieveActivities:";
        logger.debug(method);
        ActivityCollection activities = new ActivityCollection();

        List<ActivityRecord> activityList = (List<ActivityRecord>) database.findRecords(
                filter, null, new String[] { "-date" }, start, size);

        if (authorizedProfiles.contains(UserResource.ALL_PROFILES)) {
            for (ActivityRecord aRec: activityList) {
                activities.addEntry(createActivityData(aRec));
            }
        } else { // not authorized for all profiles
            for (ActivityRecord aRec: activityList) {
                logger.debug("{} record.Id= {}", method, aRec.getId());
                String type = aRec.getType();
                if ((type == null) || type.isEmpty()) {
                    logger.debug("{} record.tokenType null...getting from token record", method);
                    String tokenID = aRec.getTokenID();
                    if ((tokenID != null) && !tokenID.isEmpty()) {
                        TPSEngine engine = TPSEngine.getInstance();
                        TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
                        TokenDatabase tDatabase = subsystem.getTokenDatabase();
                        TokenRecord tRecord = tDatabase.getRecord(tokenID);
                        if (tRecord != null)
                            type = tRecord.getType();
                    }
                }

                logger.debug("{} type={}", method, type);
                if ((type == null) || type.isEmpty() || authorizedProfiles.contains(type)) {
                    logger.debug("{} token type allowed", method);
                    activities.addEntry(createActivityData(aRec));
                } else {
                    logger.debug("{} token type restricted; adding 'restricted' record", method);
                    activities.addEntry(createRestrictedActivityData());
                }
            } //for
        }
        activities.setTotal(activityList.size());
        return activities;
    }
}
