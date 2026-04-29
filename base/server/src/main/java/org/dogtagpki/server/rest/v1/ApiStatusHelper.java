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
// (C) 2025 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.rest.v1;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import java.util.Set;

/**
 * Helper class for v1 REST API status checking.
 * Centralizes the logic for reading build-time defaults and handling disabled/deprecated states.
 */
public class ApiStatusHelper {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ApiStatusHelper.class);

    /**
     * Read the default v1 API status from build.properties.
     * This value is set at build time via Maven resource filtering.
     *
     * @return The default status: "enabled", "deprecated" or "disabled"
     */
    public static String getDefaultApiStatus() {
        return System.getProperty("api.v1.status", "deprecated");
    }

    /**
     * Normalize and validate API status value.
     *
     * @param rawStatus The raw status value from system property or build default
     * @return Normalized status value (enabled, deprecated, or disabled)
     */
    private static String normalizeStatus(String rawStatus) {
        if (rawStatus == null) {
            return "deprecated";
        }

        // Normalize: trim whitespace and convert to lowercase
        String normalized = rawStatus.trim().toLowerCase();

        // Validate: only allow known values
        if ("enabled".equals(normalized) ||
            "deprecated".equals(normalized) ||
            "disabled".equals(normalized)) {
            return normalized;
        }

        // Invalid value - log warning and fall back to default
        logger.warn("Invalid api status value: '" + rawStatus + "'. " +
                   "Valid values are: enabled, deprecated, disabled. " +
                   "Falling back to 'deprecated'.");
        return "deprecated";
    }

    /**
     * Check API status and handle disabled/deprecated states.
     *
     * @param subsystemName The name of the subsystem (e.g., "CA", "KRA", "PKI")
     * @param classes The set of classes to modify if disabled or deprecated
     * @param subsystemLogger The logger to use for warnings
     * @param cs The subsystem configuration
     * @return true if the Application constructor should return early (disabled state), false otherwise
     */
    public static boolean checkApiStatus(String subsystemName, Set<Class<?>> classes, org.slf4j.Logger subsystemLogger, EngineConfig ec) {
        // Use build-time default unless overridden by system property
        String apiStatus = getDefaultApiStatus();
        if (ec != null){
            try {
                apiStatus = ec.getString("api.v1.status");
            } catch (EPropertyNotFound ep) {
                subsystemLogger.debug(subsystemName + " api.v1.status not defined");
            } catch (EBaseException eb ) {
                subsystemLogger.warn(subsystemName + " impossible to access configuration values");
            }
        }
        apiStatus = normalizeStatus(apiStatus);            
        
        if ("disabled".equals(apiStatus)) {
            subsystemLogger.debug("======================================================================");
            subsystemLogger.debug(subsystemName + " REST API V1 have been DISABLED.");
            subsystemLogger.debug("All v1 endpoints will return HTTP 404 Not Found.");
            subsystemLogger.debug("Please use v2 API instead.");
            subsystemLogger.debug("======================================================================");
            // Register only the disabled resource which returns clean error messages
            classes.add(ApiDisabledResource.class);
            return true; // return early
        }

        if ("deprecated".equals(apiStatus)) {
            subsystemLogger.debug("======================================================================");
            subsystemLogger.debug(subsystemName + " REST API V1 are DEPRECATED and will be removed in a future release.");
            subsystemLogger.debug("Please migrate to v2 API as soon as possible.");
            subsystemLogger.debug("======================================================================");
            // Register deprecation filter to add standard headers
            classes.add(ApiDeprecationFilter.class);
        }

        return false; // continue normally
    }
}
