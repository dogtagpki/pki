//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmscore.logging;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

/**
 * Provides log.instance.<id>.* parameters.
 */
public class LoggerConfig extends ConfigStore {

    public static final String TYPE = "type";
    public static final String REGISTER = "register";
    public static final String ENABLE = "enable";
    public static final String TRACE = "trace";
    public static final String LOG_SIGNING = "logSigning";
    public static final String CERT_NICKNAME = "signedAuditCertNickname";
    public static final String SELECTED_EVENTS = "events";
    public static final String MANDATORY_EVENTS = "mandatory.events";
    public static final String FILTERS = "filters";
    public static final String LEVEL = "level";
    public static final String FILE_NAME = "fileName";
    public static final String LAST_HASH_FILE_NAME = "lastHashFileName";
    public static final String BUFFER_SIZE = "bufferSize";
    public static final String FLUSH_INTERVAL = "flushInterval";

    /**
     * The default output stream buffer size in bytes
     */
    public static final int DEFAULT_BUFFER_SIZE = 512;

    /**
     * The default output flush interval in seconds
     */
    public static final int DEFAULT_FLUSH_INTERVAL = 5;

    public LoggerConfig() {
    }

    public LoggerConfig(ConfigStorage storage) {
        super(storage);
    }

    public LoggerConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    public boolean getEnable() throws EBaseException {
        return getBoolean(ENABLE, true);
    }

    public boolean getLogSigning() throws EBaseException {
        return getBoolean(LOG_SIGNING, false);
    }

    public String getSignedAuditCertNickname() throws EBaseException {
        return getString(CERT_NICKNAME);
    }

    public String getMandatoryEvents() throws EBaseException {
        return getString(MANDATORY_EVENTS, "");
    }

    public String getSelectedEvents() throws EBaseException {
        return getString(SELECTED_EVENTS, "");
    }

    public ConfigStore getFilters() throws EBaseException {
        return getSubStore(FILTERS);
    }

    public boolean getTrace() throws EBaseException {
        return getBoolean(TRACE, false);
    }

    public String getType() throws EBaseException {
        return getString(TYPE, "system");
    }

    public boolean getRegister() throws EBaseException {
        return getBoolean(REGISTER, true);
    }

    public int getLevel() throws EBaseException {
        return getInteger(LEVEL, 3);
    }

    public String getFilename(String defaultFilename) throws EBaseException {
        return getString(FILE_NAME, defaultFilename);
    }

    public int getBufferSize() throws EBaseException {
        return getInteger(BUFFER_SIZE, DEFAULT_BUFFER_SIZE);
    }

    public int getFlushInterval() throws EBaseException {
        return getInteger(FLUSH_INTERVAL, DEFAULT_FLUSH_INTERVAL);
    }
}
