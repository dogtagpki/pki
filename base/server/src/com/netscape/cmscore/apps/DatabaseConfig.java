//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmscore.apps;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.PropConfigStore;
import com.netscape.cmscore.base.SimpleProperties;
import com.netscape.cmscore.dbs.DBSubsystem;

public class DatabaseConfig extends PropConfigStore {

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
        return getBoolean(DBSubsystem.PROP_ENABLE_SERIAL_NUMBER_RECOVERY, true);
    }

    public void setEnableSerialNumberRecovery(boolean enableSerialNumberRecovery) {
        putBoolean(DBSubsystem.PROP_ENABLE_SERIAL_NUMBER_RECOVERY, enableSerialNumberRecovery);
    }

    public String getNextSerialNumber() throws EBaseException {
        return getString(DBSubsystem.PROP_NEXT_SERIAL_NUMBER, "0");
    }

    public void setNextSerialNumber(String nextSerialNumber) {
        putString(DBSubsystem.PROP_NEXT_SERIAL_NUMBER, nextSerialNumber);
    }

    public boolean getEnableSerialManagement() throws EBaseException {
        return getBoolean(DBSubsystem.PROP_ENABLE_SERIAL_MGMT, false);
    }

    public void setEnableSerialManagement(boolean enableSerialManagement) {
        putBoolean(DBSubsystem.PROP_ENABLE_SERIAL_MGMT, enableSerialManagement);
    }

    public String getSerialDN() throws EBaseException {
        return getString(DBSubsystem.PROP_SERIAL_BASEDN, "");
    }

    public void setSerialDN(String serialDN) {
        putString(DBSubsystem.PROP_SERIAL_BASEDN, serialDN);
    }

    public String getSerialRangeDN() throws EBaseException {
        return getString(DBSubsystem.PROP_SERIAL_RANGE_DN, "");
    }

    public void setSerialRangeDN(String serialRangeDN) {
        putString(DBSubsystem.PROP_SERIAL_RANGE_DN, serialRangeDN);
    }

    public String getBeginSerialNumber() throws EBaseException {
        return getString(DBSubsystem.PROP_MIN_SERIAL_NUMBER, "0");
    }

    public void setBeginSerialNumber(String beginSerialNumber) {
        putString(DBSubsystem.PROP_MIN_SERIAL_NUMBER, beginSerialNumber);
    }

    public String getEndSerialNumber() throws EBaseException {
        return getString(DBSubsystem.PROP_MAX_SERIAL_NUMBER, DBSubsystem.PROP_INFINITE_SERIAL_NUMBER);
    }

    public void setEndSerialNumber(String endSerialNumber) {
        putString(DBSubsystem.PROP_MAX_SERIAL_NUMBER, endSerialNumber);
    }

    public String getNextBeginSerialNumber() throws EBaseException {
        return getString(DBSubsystem.PROP_NEXT_MIN_SERIAL_NUMBER, "-1");
    }

    public void setNextBeginSerialNumber(String nextBeginSerialNumber) {
        putString(DBSubsystem.PROP_NEXT_MIN_SERIAL_NUMBER, nextBeginSerialNumber);
    }

    public String getNextEndSerialNumber() throws EBaseException {
        return getString(DBSubsystem.PROP_NEXT_MAX_SERIAL_NUMBER, "-1");
    }

    public void setNextEndSerialNumber(String nextEndSerialNumber) {
        putString(DBSubsystem.PROP_NEXT_MAX_SERIAL_NUMBER, nextEndSerialNumber);
    }

    public String getSerialLowWaterMark() throws EBaseException {
        return getString(DBSubsystem.PROP_SERIAL_LOW_WATER_MARK, "5000");
    }

    public void setSerialLowWaterMark(String serialLowWaterMark) {
        putString(DBSubsystem.PROP_SERIAL_LOW_WATER_MARK, serialLowWaterMark);
    }

    public String getSerialIncrement() throws EBaseException {
        return getString(DBSubsystem.PROP_SERIAL_INCREMENT, DBSubsystem.PROP_INFINITE_SERIAL_NUMBER);
    }

    public void setSerialIncrement(String serialIncrement) {
        putString(DBSubsystem.PROP_SERIAL_INCREMENT, serialIncrement);
    }

    public String getRequestDN() throws EBaseException {
        return getString(DBSubsystem.PROP_REQUEST_BASEDN, "");
    }

    public void setRequestDN(String requestDN) {
        putString(DBSubsystem.PROP_REQUEST_BASEDN, requestDN);
    }

    public String getRequestRangeDN() throws EBaseException {
        return getString(DBSubsystem.PROP_REQUEST_RANGE_DN, "");
    }

    public void setRequestRangeDN(String requestRangeDN) {
        putString(DBSubsystem.PROP_REQUEST_RANGE_DN, requestRangeDN);
    }

    public String getBeginRequestNumber() throws EBaseException {
        return getString(DBSubsystem.PROP_MIN_REQUEST_NUMBER, "0");
    }

    public void setBeginRequestNumber(String beginRequestNumber) {
        putString(DBSubsystem.PROP_MIN_REQUEST_NUMBER, beginRequestNumber);
    }

    public String getEndRequestNumber() throws EBaseException {
        return getString(DBSubsystem.PROP_MAX_REQUEST_NUMBER, DBSubsystem.PROP_INFINITE_REQUEST_NUMBER);
    }

    public void setEndRequestNumber(String endRequestNumber) {
        putString(DBSubsystem.PROP_MAX_REQUEST_NUMBER, endRequestNumber);
    }

    public String getNextBeginRequestNumber() throws EBaseException {
        return getString(DBSubsystem.PROP_NEXT_MIN_REQUEST_NUMBER, "-1");
    }

    public void setNextBeginRequestNumber(String nextBeginRequestNumber) {
        putString(DBSubsystem.PROP_NEXT_MIN_REQUEST_NUMBER, nextBeginRequestNumber);
    }

    public String getNextEndRequestNumber() throws EBaseException {
        return getString(DBSubsystem.PROP_NEXT_MAX_REQUEST_NUMBER, "-1");
    }

    public void setNextEndRequestNumber(String nextEndRequestNumber) {
        putString(DBSubsystem.PROP_NEXT_MAX_REQUEST_NUMBER, nextEndRequestNumber);
    }

    public String getRequestLowWaterMark() throws EBaseException {
        return getString(DBSubsystem.PROP_REQUEST_LOW_WATER_MARK, "5000");
    }

    public void setRequestLowWaterMark(String requestLowWaterMark) {
        putString(DBSubsystem.PROP_REQUEST_LOW_WATER_MARK, requestLowWaterMark);
    }

    public String getRequestIncrement() throws EBaseException {
        return getString(DBSubsystem.PROP_REQUEST_INCREMENT, DBSubsystem.PROP_INFINITE_REQUEST_NUMBER);
    }

    public void setRequestIncrement(String requestIncrement) {
        putString(DBSubsystem.PROP_REQUEST_INCREMENT, requestIncrement);
    }

    public String getReplicaDN() throws EBaseException {
        return getString(DBSubsystem.PROP_REPLICA_BASEDN, "");
    }

    public void setReplicaDN(String replicaDN) {
        putString(DBSubsystem.PROP_REPLICA_BASEDN, replicaDN);
    }

    public String getReplicaRangeDN() throws EBaseException {
        return getString(DBSubsystem.PROP_REPLICA_RANGE_DN, "");
    }

    public void setReplicaRangeDN(String replicaRangeDN) {
        putString(DBSubsystem.PROP_REPLICA_RANGE_DN, replicaRangeDN);
    }

    public String getBeginReplicaNumber() throws EBaseException {
        return getString(DBSubsystem.PROP_MIN_REPLICA_NUMBER, "1");
    }

    public void setBeginReplicaNumber(String beginReplicaNumber) {
        putString(DBSubsystem.PROP_MIN_REPLICA_NUMBER, beginReplicaNumber);
    }

    public String getEndReplicaNumber() throws EBaseException {
        return getString(DBSubsystem.PROP_MAX_REPLICA_NUMBER, DBSubsystem.PROP_INFINITE_REPLICA_NUMBER);
    }

    public void setEndReplicaNumber(String endReplicaNumber) {
        putString(DBSubsystem.PROP_MAX_REPLICA_NUMBER, endReplicaNumber);
    }

    public String getNextBeginReplicaNumber() throws EBaseException {
        return getString(DBSubsystem.PROP_NEXT_MIN_REPLICA_NUMBER, "-1");
    }

    public void setNextBeginReplicaNumber(String nextBeginReplicaNumber) {
        putString(DBSubsystem.PROP_NEXT_MIN_REPLICA_NUMBER, nextBeginReplicaNumber);
    }

    public String getNextEndReplicaNumber() throws EBaseException {
        return getString(DBSubsystem.PROP_NEXT_MAX_REPLICA_NUMBER, "-1");
    }

    public void setNextEndReplicaNumber(String nextEndReplicaNumber) {
        putString(DBSubsystem.PROP_NEXT_MAX_REPLICA_NUMBER, nextEndReplicaNumber);
    }

    public String getReplicaLowWaterMark() throws EBaseException {
        return getString(DBSubsystem.PROP_REPLICA_LOW_WATER_MARK, "10");
    }

    public void setReplicaLowWaterMark(String replicaLowWaterMark) {
        putString(DBSubsystem.PROP_REPLICA_LOW_WATER_MARK, replicaLowWaterMark);
    }

    public String getReplicaIncrement() throws EBaseException {
        return getString(DBSubsystem.PROP_REPLICA_INCREMENT, DBSubsystem.PROP_INFINITE_REPLICA_NUMBER);
    }

    public void setReplicaIncrement(String replicaIncrement) {
        putString(DBSubsystem.PROP_REPLICA_INCREMENT, replicaIncrement);
    }
}
