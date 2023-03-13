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
import java.net.URLEncoder;
import java.util.Date;
import java.util.List;

import javax.ws.rs.core.Response;

import org.dogtagpki.server.tps.TPSEngine;
import org.dogtagpki.server.tps.TPSSubsystem;
import org.dogtagpki.server.tps.dbs.ActivityDatabase;
import org.dogtagpki.server.tps.dbs.ActivityRecord;
import org.dogtagpki.server.tps.dbs.TokenDatabase;
import org.dogtagpki.server.tps.dbs.TokenRecord;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.dbs.DBVirtualList;
import com.netscape.certsrv.logging.ActivityCollection;
import com.netscape.certsrv.logging.ActivityData;
import com.netscape.certsrv.logging.ActivityResource;
import com.netscape.certsrv.user.UserResource;
import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cmscore.usrgrp.User;

/**
 * @author Endi S. Dewata
 */
public class ActivityService extends PKIService implements ActivityResource {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ActivityService.class);

    public ActivityService() {
        logger.debug("ActivityService.<init>()");
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
        return activityData;
    }

    /*
     * <restricted> records are records not permitted to be accessed
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

        String method = "ActivityService.findActivities: ";
        logger.debug(method);

        if (filter != null && filter.length() < MIN_FILTER_LENGTH) {
            throw new BadRequestException("Filter is too short.");
        }

        start = start == null ? 0 : start;
        size = size == null ? DEFAULT_SIZE : size;

        TPSEngine engine = TPSEngine.getInstance();
        try {
            TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
            ActivityDatabase database = subsystem.getActivityDatabase();
            ActivityCollection response = new ActivityCollection();

            if (filter == null) {
                retrieveActivitiesWithVLV(database, start, size, response);
            } else {
                retrieveActivitiesWithoutVLV(database, filter, start, size, response);
            }
            return createOKResponse(response);

        } catch (Exception e) {
            logger.error(method + e.getMessage(), e);
            throw new PKIException(e.getMessage());
        }
    }

    protected void retrieveActivitiesWithVLV(
            ActivityDatabase database,
            Integer start,
            Integer size,
            ActivityCollection response) throws Exception {

        String method = "ActivityService.retrieveActivitiesWithVLV: ";
        logger.debug(method);
        // search with VLV sorted by date in reverse order
        DBVirtualList<ActivityRecord> list = database.findRecords(
                null, null, new String[] { "-date" }, size);

        List<String> authorizedProfiles = getAuthorizedProfiles();

        int total = list.getSize();
        logger.debug(method + "total: " + total);
        int retTotal = 0; // debugging only

        // return entries in the requested page
        if (authorizedProfiles != null) {
            if (authorizedProfiles.contains(UserResource.ALL_PROFILES)) {
                for (int i = start; i < start + size && i < total; i++) {
                    ActivityRecord record = list.getElementAt(i);

                    // is it needed to check if record == null?
                    if (record == null) {
                        logger.error("ActivityService: Activity record not found");
                        throw new PKIException("Activity record not found");
                    }

                    response.addEntry(createActivityData(record));
                    retTotal++;
                }
            } else { // not authorized for all profiles
                for (int i = start; i < start + size && i < total; i++) {
                    ActivityRecord record = list.getElementAt(i);

                    //logger.debug(method + "record.Id="+ record.getId());
                    // On some rare occasions, some activities don't have
                    // their token type filled in. It is therefore necessary
                    // to get it from the token record directly.
                    String type = record.getType();
                    //logger.debug(method + "record.tokenType="+ type);
                    if ((type == null) || type.isEmpty()) {
                        logger.debug(method + "record.tokenType null...getting from token record");
                        String tokenID = record.getTokenID();
                        if ((tokenID != null) && !tokenID.isEmpty()) {
                            TPSEngine engine = TPSEngine.getInstance();
                            TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
                            TokenDatabase t_database = subsystem.getTokenDatabase();
                            TokenRecord t_record = t_database.getRecord(tokenID);
                            if (t_record != null)
                                type = t_record.getType();
                        }
                    }

                    //logger.debug(method + "type="+ type);
                    if ((type == null) || type.isEmpty() || authorizedProfiles.contains(type)) {
                        //logger.debug(method + "token type allowed");
                        retTotal++;
                        response.addEntry(createActivityData(record));
                    } else {
                        logger.debug(method + "token type restricted; adding 'restricted' record");
                        response.addEntry(createRestrictedActivityData());
                    }
                } //for
            }
        } else { //authorizedProfiles null; no permission
            logger.debug(method + "authorized profiles is null");
        }

        logger.debug(method + "retTotal = " + retTotal);
        response.setTotal(total);
    }

    protected void retrieveActivitiesWithoutVLV(
            ActivityDatabase database,
            String filter,
            Integer start,
            Integer size,
            ActivityCollection response) throws Exception {

        String method = "ActivityService.retrieveActivitiesWithoutVLV: ";
        // search without VLV
        List<ActivityRecord> activities = (List<ActivityRecord>) database.findRecords(filter);
        int total = activities.size();
        logger.debug(method + "total: " + total);

        List<String> authorizedProfiles = getAuthorizedProfiles();

        int retTotal = 0; // debugging only
        int i = 0;

        // return entries in the requested page
        if (authorizedProfiles != null) {
            if (authorizedProfiles.contains(UserResource.ALL_PROFILES)) {
                for (i= start; i < start + size && i < total; i++) {
                    ActivityRecord record = activities.get(i);

                    //logger.debug(method + "record.tokenType="+ record.getType());
                    response.addEntry(createActivityData(record));
                    retTotal++;
                }
            } else { // not authorized for all profiles
                for (i= start; i < start + size && i < total; i++) {
                    ActivityRecord record = activities.get(i);
                    //logger.debug(method + "record.ID="+ record.getId());
                    // On some rare occasions, some activities don't have
                    // their token type filled in. It is therefore necessary
                    // to get it from the token record directly.
                    String type = record.getType();
                    //logger.debug(method + "record.tokenType="+ type);
                    if ((type == null) || type.isEmpty()) {
                        logger.debug(method + "record.tokenType null...getting from token record");
                        String tokenID = record.getTokenID();
                        if ((tokenID != null) && !tokenID.isEmpty()) {
        TPSEngine engine = TPSEngine.getInstance();
            TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
                            TokenDatabase t_database = subsystem.getTokenDatabase();
                            TokenRecord t_record = t_database.getRecord(tokenID);
                            if (t_record != null)
                                type = t_record.getType();
                        }
                    }
                    //logger.debug(method + "type="+ type);

                    if ((type == null) || type.isEmpty() || authorizedProfiles.contains(type)) {
                        retTotal++;
                        response.addEntry(createActivityData(record));
                    } else {
                        //logger.debug(method + "token type not allowed: " + type +
                        //        "; adding 'restricted' record");
                        response.addEntry(createRestrictedActivityData());
                    }
                }
            }
        } else { //authorizedProfiles null; no permission
            logger.debug(method + "authorized profiles is null");
        }

        logger.debug(method + "retTotal = " + retTotal);
        response.setTotal(total);
    }

    @Override
    public Response getActivity(String activityID) {

        String method = "ActivityService.getActivity: ";
        String msg = "";
        if (activityID == null) throw new BadRequestException("Activity ID is null.");

        logger.debug(method + "(\"" + activityID + "\")");

        try {
            List<String> authorizedProfiles = getAuthorizedProfiles();
            if (authorizedProfiles == null) {
                msg = "authorizedProfiles null";
                logger.debug(method + msg);
                throw new PKIException(method + msg);
            }

            TPSEngine engine = TPSEngine.getInstance();
            TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
            ActivityDatabase database = subsystem.getActivityDatabase();
            ActivityRecord record = database.getRecord(activityID);
            if (record == null) {
                logger.debug(method + "record not found");
                throw new PKIException(method + "record not found");
            }
            String type = record.getType();

            if ((type != null) && !type.isEmpty() && !authorizedProfiles.contains(UserResource.ALL_PROFILES) && !authorizedProfiles.contains(type)) {
                msg = "token type restricted: " + type;
                logger.debug(method + msg);
                throw new PKIException(msg);
            }
            return createOKResponse(createActivityData(record));

        } catch (Exception e) {
            logger.debug(method + e.toString());
            throw new PKIException(e.getMessage());
        }
    }

    /*
     * returns a list of TPS profiles allowed for the current user
     */
    List<String> getAuthorizedProfiles()
           throws Exception {
        String method = "ActivityService.getAuthorizedProfiles: ";
        PKIPrincipal pkiPrincipal = (PKIPrincipal) servletRequest.getUserPrincipal();
        if (pkiPrincipal == null) {
            logger.debug(method + "servletRequest.getUserPrincipal() returned null");
            return null;
        }
        User user = pkiPrincipal.getUser();
        return user.getTpsProfiles();
    }
}
