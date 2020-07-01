//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//

package org.dogtagpki.ct.sct;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import org.dogtagpki.ct.LogServer;
import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAEngineConfig;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;

/**
 * @author Dinesh Prasanth M K
 *
 */
public class SCTProcessor {
    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SCTProcessor.class);

    protected IConfigStore mConfig;

    public void init() throws Exception {
        CAEngine engine = CAEngine.getInstance();
        CAEngineConfig cs = engine.getConfig();

        mConfig = cs.getCAConfig().getSubStore("certTransparency");
    }

    /*
     *  CT mode is controlled by ca.certTransparency.mode
     *  There are three CT modes:
     *      disabled: issued certs will not carry SCT extension
     *      enabled: issued certs will carry SCT extension   
     *      perProfile: certs enrolled through those profiles
     *          that contain the following policyset
     *          will carry SCT extension
     *             SignedCertificateTimestampListExtDefaultImpl
     *  cfu
     */

    public enum CTmode { disabled, enabled, perProfile };
    public CTmode getCTmode()
            throws EPropertyNotFound, EBaseException {
        String method = "SCTProcessor.CTmode: ";
        String mode = mConfig.getString("mode", "disabled");
        logger.debug(method + "CT mode =" + mode);
        switch (mode) {
            case "disabled":
                return CTmode.disabled;
            case "enabled":
                return CTmode.enabled;
            case "perProfile":
                return CTmode.perProfile;
            default:
                throw new EPropertyNotFound(method + "unknown CT mode: " + mode);
        }
    }

    /**
     * Read log server configuration from CA's CS.cfg
     *
     * Example:
     *
     * <pre>
     * {@code
     * ca.certTransparency.enable=true
     * ca.certTransparency.log.1.enable=true
     * ca.certTransparency.log.1.pubKey=MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEw8i8S7qiGEs9NXv0ZJFh6uuOmR2Q7dPprzk9XNNGkUXjzqx2SDvRfiwKYwBljfWujozHESVPQyydGaHhkaSz/g==
     * ca.certTransparency.log.1.url=http://ct.googleapis.com:80/testtube/
     * ca.certTransparency.log.1.version=1
     * ca.certTransparency.log.2.enable=false
     * ca.certTransparency.log.2.pubKey=MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKATl2B3SAbxyzGOfNRB+AytNTGvdF/FFY6HzWb+/HPE4lJ37vx2nEm99KYUy9SoNzF5VyTwCQG5nL/c5Q77yQQ==
     * ca.certTransparency.log.2.url=http://ct.googleapis.com:80/logs/crucible/
     * ca.certTransparency.log.2.version=1
     * ca.certTransparency.log.num=2
     * }
     * </pre>
     *
     * @return List of {@link org.dogtagpki.ct.LogServer} objects
     * @throws EPropertyNotFound
     * @throws EBaseException
     * @throws MalformedURLException
     */
    public List<LogServer> getLogServerConfig() throws EPropertyNotFound, EBaseException, MalformedURLException {

        IConfigStore logSubstore = mConfig.getSubStore("log");
        int numberOfLogServers = logSubstore.getInteger("num");
        List<LogServer> logServers = new ArrayList<>();

        for (int id = 1; id <= numberOfLogServers; id++) {
            logger.debug("Loading configuration for logserver ID: " + id);
            LogServer logServerConfig = new LogServer();
            IConfigStore logServerSubstore = logSubstore.getSubStore(String.valueOf(id));

            logServerConfig.setId(id);
            logServerConfig.setEnabled(logServerSubstore.getBoolean("enable"));

            logger.debug("logserver enabled: " + logServerConfig.isEnabled());

            // Skip getting more info if the log server is disabled and don't add it to the
            // logserver list
            if (!logServerConfig.isEnabled()) {
                logger.info("Logserver ID: " + id + " has been disabled. Skipping this specific logserver");
                continue;
            }

            logServerConfig.setPublicKey(logServerSubstore.getString("pubKey"));
            logServerConfig.setVersion(logServerSubstore.getInteger("version"));

            URL url = new URL(logServerSubstore.getString("url"));
            logServerConfig.setUrl(url);

            logServers.add(logServerConfig);
        }

        return logServers;

    }

}
