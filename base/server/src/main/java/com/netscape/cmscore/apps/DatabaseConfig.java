//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmscore.apps;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;
import com.netscape.cmscore.ldapconn.LDAPConfig;

/**
 * Provides dbs.* parameters.
 */
public class DatabaseConfig extends ConfigStore {

    public static final String ENABLE_SERIAL_NUMBER_RECOVERY = "enableSerialNumberRecovery";

    /**
     * This value is only equal to the next serial number that the CA is
     * going to issue when the server just start up or it's just set from console.
     * It doesn't record the next serial number at other time when the server
     * is running not to increase overhead when issuing certs.
     */
    public static final String NEXT_SERIAL_NUMBER = "nextSerialNumber";

    public static final String MIN_SERIAL_NUMBER = "beginSerialNumber";
    public static final String MAX_SERIAL_NUMBER = "endSerialNumber";

    public static final String NEXT_MIN_SERIAL_NUMBER = "nextBeginSerialNumber";
    public static final String NEXT_MAX_SERIAL_NUMBER = "nextEndSerialNumber";

    public static final String SERIAL_LOW_WATER_MARK = "serialLowWaterMark";
    public static final String SERIAL_INCREMENT = "serialIncrement";

    public static final String SERIAL_BASEDN = "serialDN";
    public static final String SERIAL_RANGE_DN = "serialRangeDN";

    public static final String MIN_REQUEST_NUMBER = "beginRequestNumber";
    public static final String MAX_REQUEST_NUMBER = "endRequestNumber";

    public static final String NEXT_MIN_REQUEST_NUMBER = "nextBeginRequestNumber";
    public static final String NEXT_MAX_REQUEST_NUMBER = "nextEndRequestNumber";

    public static final String REQUEST_LOW_WATER_MARK = "requestLowWaterMark";
    public static final String REQUEST_INCREMENT = "requestIncrement";

    public static final String REQUEST_BASEDN = "requestDN";
    public static final String REQUEST_RANGE_DN = "requestRangeDN";

    public static final String MIN_REPLICA_NUMBER = "beginReplicaNumber";
    public static final String MAX_REPLICA_NUMBER = "endReplicaNumber";

    public static final String NEXT_MIN_REPLICA_NUMBER = "nextBeginReplicaNumber";
    public static final String NEXT_MAX_REPLICA_NUMBER = "nextEndReplicaNumber";

    public static final String REPLICA_LOW_WATER_MARK = "replicaLowWaterMark";
    public static final String REPLICA_INCREMENT = "replicaIncrement";

    public static final String REPLICA_BASEDN = "replicaDN";
    public static final String REPLICA_RANGE_DN = "replicaRangeDN";

    public static final String INFINITE_SERIAL_NUMBER = "1000000000";
    public static final String INFINITE_REQUEST_NUMBER = "1000000000";
    public static final String INFINITE_REPLICA_NUMBER = "1000";

    public static final String ENABLE_SERIAL_MGMT = "enableSerialManagement";

    public DatabaseConfig(ConfigStorage storage) {
        super(storage);
    }

    public DatabaseConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    public String getNewSchemaEntryAdded() throws EBaseException {
        return getString("newSchemaEntryAdded", "");
    }

    public void setNewSchemaEntryAdded(String newSchemaEntryAdded) {
        putString("newSchemaEntryAdded", newSchemaEntryAdded);
    }

    public boolean getEnableSerialNumberRecovery() throws EBaseException {
        return getBoolean(ENABLE_SERIAL_NUMBER_RECOVERY, true);
    }

    public void setEnableSerialNumberRecovery(boolean enableSerialNumberRecovery) {
        putBoolean(ENABLE_SERIAL_NUMBER_RECOVERY, enableSerialNumberRecovery);
    }

    public String getNextSerialNumber() throws EBaseException {
        return getString(NEXT_SERIAL_NUMBER, "0");
    }

    public void setNextSerialNumber(String nextSerialNumber) {
        putString(NEXT_SERIAL_NUMBER, nextSerialNumber);
    }

    public boolean getEnableSerialManagement() throws EBaseException {
        return getBoolean(ENABLE_SERIAL_MGMT, false);
    }

    public void setEnableSerialManagement(boolean enableSerialManagement) {
        putBoolean(ENABLE_SERIAL_MGMT, enableSerialManagement);
    }

    public String getSerialDN() throws EBaseException {
        return getString(SERIAL_BASEDN, "");
    }

    public void setSerialDN(String serialDN) {
        putString(SERIAL_BASEDN, serialDN);
    }

    public String getSerialRangeDN() throws EBaseException {
        return getString(SERIAL_RANGE_DN, "");
    }

    public void setSerialRangeDN(String serialRangeDN) {
        putString(SERIAL_RANGE_DN, serialRangeDN);
    }

    public String getBeginSerialNumber() throws EBaseException {
        return getString(MIN_SERIAL_NUMBER, "0");
    }

    public void setBeginSerialNumber(String beginSerialNumber) {
        putString(MIN_SERIAL_NUMBER, beginSerialNumber);
    }

    public String getEndSerialNumber() throws EBaseException {
        return getString(MAX_SERIAL_NUMBER, INFINITE_SERIAL_NUMBER);
    }

    public void setEndSerialNumber(String endSerialNumber) {
        putString(MAX_SERIAL_NUMBER, endSerialNumber);
    }

    public String getNextBeginSerialNumber() throws EBaseException {
        return getString(NEXT_MIN_SERIAL_NUMBER, "-1");
    }

    public void setNextBeginSerialNumber(String nextBeginSerialNumber) {
        putString(NEXT_MIN_SERIAL_NUMBER, nextBeginSerialNumber);
    }

    public void removeNextBeginSerialNumber() throws EBaseException {
        remove(NEXT_MIN_SERIAL_NUMBER);
    }

    public String getNextEndSerialNumber() throws EBaseException {
        return getString(NEXT_MAX_SERIAL_NUMBER, "-1");
    }

    public void setNextEndSerialNumber(String nextEndSerialNumber) {
        putString(NEXT_MAX_SERIAL_NUMBER, nextEndSerialNumber);
    }

    public void removeNextEndSerialNumber() throws EBaseException {
        remove(NEXT_MAX_SERIAL_NUMBER);
    }

    public String getSerialLowWaterMark() throws EBaseException {
        return getString(SERIAL_LOW_WATER_MARK, "5000");
    }

    public void setSerialLowWaterMark(String serialLowWaterMark) {
        putString(SERIAL_LOW_WATER_MARK, serialLowWaterMark);
    }

    public String getSerialIncrement() throws EBaseException {
        return getString(SERIAL_INCREMENT, INFINITE_SERIAL_NUMBER);
    }

    public void setSerialIncrement(String serialIncrement) {
        putString(SERIAL_INCREMENT, serialIncrement);
    }

    public String getRequestDN() throws EBaseException {
        return getString(REQUEST_BASEDN, "");
    }

    public void setRequestDN(String requestDN) {
        putString(REQUEST_BASEDN, requestDN);
    }

    public String getRequestRangeDN() throws EBaseException {
        return getString(REQUEST_RANGE_DN, "");
    }

    public void setRequestRangeDN(String requestRangeDN) {
        putString(REQUEST_RANGE_DN, requestRangeDN);
    }

    public String getBeginRequestNumber() throws EBaseException {
        return getString(MIN_REQUEST_NUMBER, "0");
    }

    public void setBeginRequestNumber(String beginRequestNumber) {
        putString(MIN_REQUEST_NUMBER, beginRequestNumber);
    }

    public String getEndRequestNumber() throws EBaseException {
        return getString(MAX_REQUEST_NUMBER, INFINITE_REQUEST_NUMBER);
    }

    public void setEndRequestNumber(String endRequestNumber) {
        putString(MAX_REQUEST_NUMBER, endRequestNumber);
    }

    public String getNextBeginRequestNumber() throws EBaseException {
        return getString(NEXT_MIN_REQUEST_NUMBER, "-1");
    }

    public void setNextBeginRequestNumber(String nextBeginRequestNumber) {
        putString(NEXT_MIN_REQUEST_NUMBER, nextBeginRequestNumber);
    }

    public void removeNextBeginRequestNumber() throws EBaseException {
        remove(NEXT_MIN_REQUEST_NUMBER);
    }

    public String getNextEndRequestNumber() throws EBaseException {
        return getString(NEXT_MAX_REQUEST_NUMBER, "-1");
    }

    public void setNextEndRequestNumber(String nextEndRequestNumber) {
        putString(NEXT_MAX_REQUEST_NUMBER, nextEndRequestNumber);
    }

    public void removeNextEndRequestNumber() throws EBaseException {
        remove(NEXT_MAX_REQUEST_NUMBER);
    }

    public String getRequestLowWaterMark() throws EBaseException {
        return getString(REQUEST_LOW_WATER_MARK, "5000");
    }

    public void setRequestLowWaterMark(String requestLowWaterMark) {
        putString(REQUEST_LOW_WATER_MARK, requestLowWaterMark);
    }

    public String getRequestIncrement() throws EBaseException {
        return getString(REQUEST_INCREMENT, INFINITE_REQUEST_NUMBER);
    }

    public void setRequestIncrement(String requestIncrement) {
        putString(REQUEST_INCREMENT, requestIncrement);
    }

    public String getReplicaDN() throws EBaseException {
        return getString(REPLICA_BASEDN, "");
    }

    public void setReplicaDN(String replicaDN) {
        putString(REPLICA_BASEDN, replicaDN);
    }

    public String getReplicaRangeDN() throws EBaseException {
        return getString(REPLICA_RANGE_DN, "");
    }

    public void setReplicaRangeDN(String replicaRangeDN) {
        putString(REPLICA_RANGE_DN, replicaRangeDN);
    }

    public String getBeginReplicaNumber() throws EBaseException {
        return getString(MIN_REPLICA_NUMBER, "1");
    }

    public void setBeginReplicaNumber(String beginReplicaNumber) {
        putString(MIN_REPLICA_NUMBER, beginReplicaNumber);
    }

    public String getEndReplicaNumber() throws EBaseException {
        return getString(MAX_REPLICA_NUMBER, INFINITE_REPLICA_NUMBER);
    }

    public void setEndReplicaNumber(String endReplicaNumber) {
        putString(MAX_REPLICA_NUMBER, endReplicaNumber);
    }

    public String getNextBeginReplicaNumber() throws EBaseException {
        return getString(NEXT_MIN_REPLICA_NUMBER, "-1");
    }

    public void setNextBeginReplicaNumber(String nextBeginReplicaNumber) {
        putString(NEXT_MIN_REPLICA_NUMBER, nextBeginReplicaNumber);
    }

    public void removeNextBeginReplicaNumber() throws EBaseException {
        remove(NEXT_MIN_REPLICA_NUMBER);
    }

    public String getNextEndReplicaNumber() throws EBaseException {
        return getString(NEXT_MAX_REPLICA_NUMBER, "-1");
    }

    public void setNextEndReplicaNumber(String nextEndReplicaNumber) {
        putString(NEXT_MAX_REPLICA_NUMBER, nextEndReplicaNumber);
    }

    public void removeNextEndReplicaNumber() throws EBaseException {
        remove(NEXT_MAX_REPLICA_NUMBER);
    }

    public String getReplicaLowWaterMark() throws EBaseException {
        return getString(REPLICA_LOW_WATER_MARK, "10");
    }

    public void setReplicaLowWaterMark(String replicaLowWaterMark) {
        putString(REPLICA_LOW_WATER_MARK, replicaLowWaterMark);
    }

    public String getReplicaIncrement() throws EBaseException {
        return getString(REPLICA_INCREMENT, INFINITE_REPLICA_NUMBER);
    }

    public void setReplicaIncrement(String replicaIncrement) {
        putString(REPLICA_INCREMENT, replicaIncrement);
    }

    public LDAPConfig getLDAPConfig() throws EBaseException {
        return getSubStore("ldap", LDAPConfig.class);
    }
}
