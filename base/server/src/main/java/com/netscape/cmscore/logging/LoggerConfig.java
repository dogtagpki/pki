//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmscore.logging;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cms.logging.LogFile;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

/**
 * Provides log.instance.<id>.* parameters.
 */
public class LoggerConfig extends ConfigStore {

    public LoggerConfig() {
    }

    public LoggerConfig(ConfigStorage storage) {
        super(storage);
    }

    public LoggerConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    public boolean getEnable() throws EBaseException {
        return getBoolean(LogFile.PROP_ON, true);
    }

    public boolean getLogSigning() throws EBaseException {
        return getBoolean(LogFile.PROP_SIGNED_AUDIT_LOG_SIGNING, false);
    }

    public String getSignedAuditCertNickname() throws EBaseException {
        return getString(LogFile.PROP_SIGNED_AUDIT_CERT_NICKNAME);
    }

    public String getMandatoryEvents() throws EBaseException {
        return getString(LogFile.PROP_SIGNED_AUDIT_MANDATORY_EVENTS, "");
    }

    public String getSelectedEvents() throws EBaseException {
        return getString(LogFile.PROP_SIGNED_AUDIT_SELECTED_EVENTS, "");
    }

    public ConfigStore getFilters() throws EBaseException {
        return getSubStore(LogFile.PROP_SIGNED_AUDIT_FILTERS);
    }

    public boolean getTrace() throws EBaseException {
        return getBoolean(LogFile.PROP_TRACE, false);
    }

    public String getType() throws EBaseException {
        return getString(LogFile.PROP_TYPE, "system");
    }

    public boolean getRegister() throws EBaseException {
        return getBoolean(LogFile.PROP_REGISTER, true);
    }

    public int getLevel() throws EBaseException {
        return getInteger(LogFile.PROP_LEVEL, 3);
    }

    public String getFilename(String defaultFilename) throws EBaseException {
        return getString(LogFile.PROP_FILE_NAME, defaultFilename);
    }

    public int getBufferSize() throws EBaseException {
        return getInteger(LogFile.PROP_BUFFER_SIZE, LogFile.BUFFER_SIZE);
    }

    public int getFlushInterval() throws EBaseException {
        return getInteger(LogFile.PROP_FLUSH_INTERVAL, LogFile.FLUSH_INTERVAL);
    }
}
