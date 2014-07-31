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

package org.dogtagpki.server.tps.dbs;

import java.util.Calendar;
import java.util.Date;

import org.apache.commons.lang.StringUtils;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.IDBSubsystem;
import com.netscape.cmscore.dbs.LDAPDatabase;
import com.netscape.cmsutil.ldap.LDAPUtil;

/**
 * This class implements in-memory activity database. In the future this
 * will be replaced with LDAP database.
 *
 * @author Endi S. Dewata
 */
public class ActivityDatabase extends LDAPDatabase<ActivityRecord> {
    public final static String OP_DO_TOKEN = "do_token";
    public final static String OP_ADD = "add"; // add a token
    public final static String OP_DELETE = "delete"; // delete a token
    //public final static String OP_MODIFY_AUDIT_SIGNING = "modify_audit_signing";
    public final static String OP_ENROLLMENT = "enrollment";
    public final static String OP_RENEWAL = "renewal";
    public final static String OP_PIN_RESET = "pin_reset";
    public final static String OP_FORMAT = "format";

    public ActivityDatabase(IDBSubsystem dbSubsystem, String baseDN) throws EBaseException {
        super("Activity", dbSubsystem, baseDN, ActivityRecord.class);
    }

    public ActivityRecord log(
            String ip, String tokenID, String operation, String result,
            String message, String userID, String tokenType) throws Exception {

        Calendar c = Calendar.getInstance();
        int year = c.get(Calendar.YEAR);
        int month = c.get(Calendar.MONTH) + 1;
        int day = c.get(Calendar.DAY_OF_MONTH);
        int hour = c.get(Calendar.HOUR_OF_DAY);
        int minute = c.get(Calendar.MINUTE);
        int second = c.get(Calendar.SECOND);
        int microSecond = c.get(Calendar.MILLISECOND) * 1000;
        long threadID = Thread.currentThread().getId();

        String id = String.format(
                "%04d%02d%02d%02d%02d%02d%06d.%x",
                year, month, day,
                hour, minute, second, microSecond,
                threadID);

        ActivityRecord activityRecord = new ActivityRecord();
        activityRecord.setId(id);
        activityRecord.setIP(ip);
        activityRecord.setTokenID(tokenID);
        activityRecord.setOperation(operation);
        activityRecord.setResult(result);
        activityRecord.setMessage(message);
        activityRecord.setUserID(userID);
        activityRecord.setType(tokenType);
        activityRecord.setDate(c.getTime());

        super.addRecord(id, activityRecord);

        return activityRecord;
    }

    @Override
    public void addRecord(String id, ActivityRecord activityRecord) throws Exception {
        activityRecord.setDate(new Date());

        super.addRecord(id, activityRecord);
    }

    @Override
    public String createDN(String id) {
        return "cn=" + id + "," + baseDN;
    }

    @Override
    public String createFilter(String filter) {

        if (StringUtils.isEmpty(filter)) {
            return "(id=*)";
        }

        filter = LDAPUtil.escapeFilter(filter);
        return "(|(tokenID=*" + filter + "*)(userID=*" + filter + "*))";
    }
}
