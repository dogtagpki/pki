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

package org.dogtagpki.server.rest;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.StreamingOutput;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.logging.AuditConfig;
import com.netscape.certsrv.logging.AuditFile;
import com.netscape.certsrv.logging.AuditFileCollection;
import com.netscape.certsrv.logging.AuditLogFindRequest;
import com.netscape.certsrv.logging.AuditResource;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cms.servlet.base.SubsystemService;

/**
 * @author Endi S. Dewata
 */
public class AuditService extends SubsystemService implements AuditResource {

    public AuditService() {
        CMS.debug("AuditService.<init>()");
    }

    public AuditConfig createAuditConfig() throws UnsupportedEncodingException, EBaseException {
        return createAuditConfig(null);
    }

    public AuditConfig createAuditConfig(Map<String, String> auditParams)
            throws UnsupportedEncodingException, EBaseException {

        IConfigStore cs = CMS.getConfigStore();

        AuditConfig auditConfig = new AuditConfig();
        String val = null;
        Boolean boolval = false;
        Integer integerval;

        val = cs.getBoolean("log.instance.SignedAudit.enable", false) ? "Enabled" : "Disabled";
        auditConfig.setStatus(val);
        if (auditParams != null)
            auditParams.put("enable", val);

        boolval = cs.getBoolean("log.instance.SignedAudit.logSigning", false);
        if (auditParams != null)
            auditParams.put("logSigning", boolval ? "true" : "false");
        auditConfig.setSigned(boolval);

        integerval = cs.getInteger("log.instance.SignedAudit.flushInterval", 5);
        auditConfig.setInterval(integerval);
        if (auditParams != null)
            auditParams.put("flushInterval", integerval.toString());

        integerval = cs.getInteger("log.instance.SignedAudit.bufferSize", 512);
        auditConfig.setBufferSize(integerval);
        if (auditParams != null)
            auditParams.put("bufferSize", integerval.toString());

        Map<String, String> eventConfigs = new TreeMap<String, String>();

        // unselected optional events
        val = cs.getString("log.instance.SignedAudit.unselected.events", "");
        if (auditParams != null)
            auditParams.put("unselected.events", val);
        for (String event : StringUtils.split(val, ", ")) {
            eventConfigs.put(event.trim(), "disabled");
        }

        // selected optional events
        val = cs.getString("log.instance.SignedAudit.events", "");
        if (auditParams != null)
            auditParams.put("events", val);
        for (String event : StringUtils.split(val, ", ")) {
            eventConfigs.put(event.trim(), "enabled");
        }

        // always selected mandatory events
        val = cs.getString("log.instance.SignedAudit.mandatory.events", "");
        if (auditParams != null)
            auditParams.put("mandatory.events", val);
        for (String event : StringUtils.split(val, ", ")) {
            eventConfigs.put(event.trim(), "mandatory");
        }

        auditConfig.setEventConfigs(eventConfigs);

        URI uri = uriInfo.getBaseUriBuilder().path(AuditResource.class).build();
        auditConfig.setLink(new Link("self", uri));

        return auditConfig;
    }

    @Override
    public Response getAuditConfig() {

        CMS.debug("AuditService.getAuditConfig()");

        try {
            return createOKResponse(createAuditConfig());

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response updateAuditConfig(AuditConfig auditConfig) {
        Map<String, String> auditModParams = new HashMap<String, String>();

        if (auditConfig == null) {
            BadRequestException e = new BadRequestException("Audit config is null.");
            auditModParams.put("Info", e.toString());
            auditTPSConfigSignedAudit(ILogger.FAILURE, auditModParams);
            throw e;
        }

        CMS.debug("AuditService.updateAuditConfig()");

        try {
            AuditConfig currentAuditConfig = createAuditConfig();
            Map<String, String> currentEventConfigs = currentAuditConfig.getEventConfigs();

            IConfigStore cs = CMS.getConfigStore();

            if (auditConfig.getSigned() != null) {
                cs.putBoolean("log.instance.SignedAudit.logSigning", auditConfig.getSigned());
            }

            if (auditConfig.getInterval() != null) {
                cs.putInteger("log.instance.SignedAudit.flushInterval", auditConfig.getInterval());
            }

            if (auditConfig.getBufferSize() != null) {
                cs.putInteger("log.instance.SignedAudit.bufferSize", auditConfig.getBufferSize());
            }

            Map<String, String> eventConfigs = auditConfig.getEventConfigs();

            if (eventConfigs != null) {
                // update events if specified

                Collection<String> selected = new TreeSet<String>();
                Collection<String> unselected = new TreeSet<String>();

                for (Map.Entry<String, String> entry : eventConfigs.entrySet()) {
                    String name = entry.getKey();
                    String value = entry.getValue();
                    String currentValue = currentEventConfigs.get(name);

                    // make sure no event is added
                    if (currentValue == null) {
                        PKIException e = new PKIException("Unable to add event: " + name);
                        auditModParams.put("Info", e.toString());
                        auditTPSConfigSignedAudit(ILogger.FAILURE, auditModParams);
                        throw e;
                    }

                    // make sure no optional event becomes mandatory
                    if ("mandatory".equals(value)) {
                        if (!"mandatory".equals(currentValue)) {
                            PKIException e = new PKIException("Unable to add mandatory event: " + name);
                            auditModParams.put("Info", e.toString());
                            auditTPSConfigSignedAudit(ILogger.FAILURE, auditModParams);
                            throw e;
                        }
                        continue;
                    }

                    // make sure no mandatory event becomes optional
                    if ("mandatory".equals(currentValue)) {
                        PKIException e = new PKIException("Unable to remove mandatory event: " + name);
                        auditModParams.put("Info", e.toString());
                        auditTPSConfigSignedAudit(ILogger.FAILURE, auditModParams);
                        throw e;
                    }

                    if ("enabled".equals(value)) {
                        selected.add(name);

                    } else if ("disabled".equals(value)) {
                        unselected.add(name);

                    } else {
                        PKIException e = new PKIException("Invalid event configuration: " + name + "=" + value);
                        auditModParams.put("Info", e.toString());
                        auditTPSConfigSignedAudit(ILogger.FAILURE, auditModParams);
                        throw e;
                    }
                }

                cs.putString("log.instance.SignedAudit.events", StringUtils.join(selected, ","));
                cs.putString("log.instance.SignedAudit.unselected.events", StringUtils.join(unselected, ","));
            }

            for (String name : currentEventConfigs.keySet()) {
                // make sure no event is removed
                if (!eventConfigs.containsKey(name)) {
                    PKIException e = new PKIException("Unable to remove event: " + name);
                    auditModParams.put("Info", e.toString());
                    auditTPSConfigSignedAudit(ILogger.FAILURE, auditModParams);
                    throw e;
                }
            }

            cs.commit(true);

            auditConfig = createAuditConfig(auditModParams);
            auditTPSConfigSignedAudit(ILogger.SUCCESS, auditModParams);

            return createOKResponse(auditConfig);

        } catch (PKIException e) {
            auditModParams.put("Info", e.toString());
            auditTPSConfigSignedAudit(ILogger.FAILURE, auditModParams);
            throw e;

        } catch (Exception e) {
            auditModParams.put("Info", e.toString());
            auditTPSConfigSignedAudit(ILogger.FAILURE, auditModParams);
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response changeAuditStatus(String action) {
        Map<String, String> auditModParams = new HashMap<String, String>();

        CMS.debug("AuditService.changeAuditStatus()");

        try {
            auditModParams.put("Action", action);
            IConfigStore cs = CMS.getConfigStore();

            if ("enable".equals(action)) {
                cs.putBoolean("log.instance.SignedAudit.enable", true);

            } else if ("disable".equals(action)) {
                cs.putBoolean("log.instance.SignedAudit.enable", false);

            } else {
                BadRequestException e = new BadRequestException("Invalid action " + action);
                auditModParams.put("Info", e.toString());
                auditTPSConfigSignedAudit(ILogger.FAILURE, auditModParams);
                throw e;
            }

            cs.commit(true);

            AuditConfig auditConfig = createAuditConfig();
            auditTPSConfigSignedAudit(ILogger.SUCCESS, auditModParams);

            return createOKResponse(auditConfig);

        } catch (PKIException e) {
            auditModParams.put("Info", e.toString());
            auditTPSConfigSignedAudit(ILogger.FAILURE, auditModParams);
            e.printStackTrace();
            throw e;

        } catch (Exception e) {
            auditModParams.put("Info", e.toString());
            auditTPSConfigSignedAudit(ILogger.FAILURE, auditModParams);
            e.printStackTrace();
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    public File getCurrentLogFile() {
        IConfigStore cs = CMS.getConfigStore();
        String filename = cs.get("log.instance.SignedAudit.fileName");
        return new File(filename);
    }

    public File getLogDirectory() {
        File file = getCurrentLogFile();
        return file.getParentFile();
    }

    public List<File> getLogFiles() {

        List<String> filenames = new ArrayList<>();

        File currentFile = getCurrentLogFile();
        String currentFilename = currentFile.getName();
        File logDir = currentFile.getParentFile();

        // add all log files except the current one
        for (String filename : logDir.list()) {
            if (filename.equals(currentFilename)) continue;
            filenames.add(filename);
        }

        // sort log files in ascending order
        Collections.sort(filenames);

        // add the current log file last (i.e. newest)
        filenames.add(currentFilename);

        List<File> files = new ArrayList<>();
        for (String filename : filenames) {
            files.add(new File(logDir, filename));
        }

        return files;
    }

    @Override
    public Response findAuditFiles() {

        AuditFileCollection response = new AuditFileCollection();

        List<File> files = getLogFiles();

        CMS.debug("Audit files:");
        for (File file : files) {
            String name = file.getName();
            CMS.debug(" - " + name);

            AuditFile auditFile = new AuditFile();
            auditFile.setName(name);
            auditFile.setSize(file.length());

            response.addEntry(auditFile);
        }

        response.setTotal(files.size());

        return createOKResponse(response);
    }

    @Override
    public Response getAuditFile(String filename) {
        AuditLogFindRequest request = new AuditLogFindRequest();
        request.setFileName(filename);
        return findAuditLogs(request);
    }
/*
    @Override
    public Response removeAuditFile(String filename) {

        // make sure filename does not contain path
        if (!new File(filename).getName().equals(filename)) {
            CMS.debug("Invalid file name: " + filename);
            throw new BadRequestException("Invalid file name: " + filename);
        }

        File logDir = getLogDirectory();
        File file = new File(logDir, filename);

        if (!file.exists()) {
            throw new ResourceNotFoundException("File not found: " + filename);
        }

        file.delete();
        return createNoContentResponse();
    }
*/
    @Override
    public Response findAuditLogs(AuditLogFindRequest request) {

        Collection<File> files;

        String filename = request.getFileName();
        if (filename == null) {
            // retrieve logs from all files
            files = getLogFiles();

        } else {
            // make sure filename does not contain path
            if (!new File(filename).getName().equals(filename)) {
                CMS.debug("Invalid file name: " + filename);
                throw new BadRequestException("Invalid file name: " + filename);
            }

            File logDir = getLogDirectory();
            File file = new File(logDir, filename);

            if (!file.exists()) {
                throw new ResourceNotFoundException("File not found: " + filename);
            }

            // retrieve logs from the specified file only
            files = new ArrayList<>();
            files.add(file);
        }

        StreamingOutput so = new StreamingOutput() {

            @Override
            public void write(OutputStream out) throws IOException, WebApplicationException {

                CMS.debug("Audit files:");
                for (File file : files) {
                    String name = file.getName();
                    CMS.debug(" - " + name);

                    try (InputStream is = new FileInputStream(file)) {
                        IOUtils.copy(is, out);
                    }
                }
            }
        };

        return createOKResponse(so);
    }

    /*
     * in case of failure, "info" should be in the params
     */
    public void auditTPSConfigSignedAudit(String status, Map<String, String> params) {

        String msg = CMS.getLogMessage(
                "LOGGING_SIGNED_AUDIT_CONFIG_SIGNED_AUDIT_3",
                servletRequest.getUserPrincipal().getName(),
                status,
                auditor.getParamString(null, params));
        auditor.log(msg);

    }
}
