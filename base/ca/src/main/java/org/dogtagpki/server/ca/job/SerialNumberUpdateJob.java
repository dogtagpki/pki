//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.job;

import java.util.Calendar;
import java.util.Date;

import org.dogtagpki.server.ca.CAEngine;

import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.cms.jobs.Job;

public class SerialNumberUpdateJob extends Job implements IExtendedPluginInfo {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SerialNumberUpdateJob.class);

    public SerialNumberUpdateJob() {
    }

    @Override
    public String[] getConfigParams() {
        return null;
    }

    @Override
    public String[] getExtendedPluginInfo() {
        return null;
    }

    @Override
    public void run() {
        Calendar calendar = Calendar.getInstance();
        Date time = calendar.getTime();
        logger.info("SerialNumberUpdateJob: Running " + mId + " job at " + time);

        try {
            CAEngine engine = (CAEngine) super.engine;
            engine.updateSerialNumbers();
        } catch (Exception e) {
            logger.warn("SerialNumberUpdateJob: " + e.getMessage(), e);
        }
    }
}
