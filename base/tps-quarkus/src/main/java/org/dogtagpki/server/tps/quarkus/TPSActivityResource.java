//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.quarkus;

import java.util.Date;
import java.util.List;

import jakarta.inject.Inject;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

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

import io.quarkus.security.identity.SecurityIdentity;

/**
 * JAX-RS resource for TPS activity operations.
 * Replaces ActivityServlet.
 *
 * Activities are filtered by the user's authorized TPS profiles.
 * Unauthorized activities are shown as restricted records.
 */
@Path("v2/activities")
public class TPSActivityResource {

    private static final Logger logger = LoggerFactory.getLogger(TPSActivityResource.class);
    private static final int MIN_FILTER_LENGTH = 3;
    private static final int DEFAULT_SIZE = 20;

    @Inject
    TPSEngineQuarkus engineQuarkus;

    @Inject
    SecurityIdentity identity;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response findActivities(
            @QueryParam("filter") String filter,
            @QueryParam("start") @DefaultValue("0") int start,
            @QueryParam("size") @DefaultValue("20") int size) throws Exception {

        TPSSubsystem subsystem = engineQuarkus.getSubsystem();
        ActivityDatabase database = subsystem.getActivityDatabase();
        List<String> authorizedProfiles = TPSEngineQuarkus.getAuthorizedProfiles(identity);
        if (authorizedProfiles.isEmpty()) {
            throw new UnauthorizedException("User not authorized");
        }

        if (filter != null && filter.length() < MIN_FILTER_LENGTH) {
            throw new BadRequestException("Filter is too short.");
        }

        ActivityCollection activities = retrieveActivities(database, authorizedProfiles, filter, start, size);
        return Response.ok(activities.toJSON()).build();
    }

    @GET
    @Path("{activityId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getActivity(@PathParam("activityId") String activityId) throws Exception {
        String method = "TPSActivityResource.getActivity:";
        TPSSubsystem subsystem = engineQuarkus.getSubsystem();
        ActivityDatabase database = subsystem.getActivityDatabase();
        List<String> authorizedProfiles = TPSEngineQuarkus.getAuthorizedProfiles(identity);
        if (authorizedProfiles.isEmpty()) {
            throw new UnauthorizedException("User not authorized");
        }

        if (activityId == null || activityId.isBlank()) {
            throw new BadRequestException("Id is empty");
        }

        ActivityRecord aRec;
        try {
            aRec = database.getRecord(activityId);
        } catch (Exception e) {
            logger.debug("{} error retrieving the activity record", method, e);
            throw new ResourceNotFoundException("Record " + activityId + " not found");
        }
        if (aRec == null) {
            throw new ResourceNotFoundException("Record " + activityId + " not found");
        }

        String type = aRec.getType();
        if ((type != null) && !type.isEmpty() &&
                !authorizedProfiles.contains(UserResource.ALL_PROFILES) &&
                !authorizedProfiles.contains(type)) {
            throw new PKIException("token type restricted: " + type);
        }

        ActivityData data = createActivityData(aRec);
        return Response.ok(data.toJSON()).build();
    }

    private ActivityCollection retrieveActivities(ActivityDatabase database,
            List<String> authorizedProfiles, String filter, int start, int size) throws Exception {

        ActivityCollection activities = new ActivityCollection();
        List<ActivityRecord> activityList = (List<ActivityRecord>) database.findRecords(
                filter, null, new String[]{"-date"}, start, size);

        if (authorizedProfiles.contains(UserResource.ALL_PROFILES)) {
            for (ActivityRecord aRec : activityList) {
                activities.addEntry(createActivityData(aRec));
            }
        } else {
            for (ActivityRecord aRec : activityList) {
                String type = aRec.getType();
                if ((type == null) || type.isEmpty()) {
                    String tokenID = aRec.getTokenID();
                    if ((tokenID != null) && !tokenID.isEmpty()) {
                        TPSSubsystem subsystem = engineQuarkus.getSubsystem();
                        TokenDatabase tDatabase = subsystem.getTokenDatabase();
                        TokenRecord tRecord = tDatabase.getRecord(tokenID);
                        if (tRecord != null) {
                            type = tRecord.getType();
                        }
                    }
                }

                if ((type == null) || type.isEmpty() || authorizedProfiles.contains(type)) {
                    activities.addEntry(createActivityData(aRec));
                } else {
                    activities.addEntry(createRestrictedActivityData());
                }
            }
        }
        activities.setTotal(activityList.size());
        return activities;
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

    private ActivityData createRestrictedActivityData() {
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
}
