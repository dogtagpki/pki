//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.rest.filter;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;

/**
 * Servlet filter for REST API version control.
 *
 * Provides runtime control over which REST API versions are enabled/disabled
 * and adds deprecation warnings to deprecated API versions.
 *
 * Build-time configuration (rest-api.properties):
 * - deprecated.version: API version marked as deprecated
 * - disabled.versions: API versions disabled by default at build time
 *
 * Runtime configuration for CMSEngine (CS.cfg):
 * - rest.api.enabled: Comma-separated list of versions to enable (overrides build-time disabled)
 * - rest.api.suppress_deprecation_warnings: Boolean to suppress deprecation headers
 *
 * Runtime configuration for PKIEngine (rest-api-option.properties):
 * - deprecated.version: Override deprecated API version
 * - disabled.versions: Comma-separated list of versions to disable
 * - suppress_deprecation_warnings: Boolean to suppress deprecation headers
 *
 * The rest-api-option.properties file overrides build-time settings from rest-api.properties.
 *
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebFilter(
    filterName = "APIVersionFilter",
    urlPatterns = {"/*"}
)
public class APIVersionFilter implements Filter {

    private static Logger logger = LoggerFactory.getLogger(APIVersionFilter.class);

    private String deprecatedVersion;
    private Set<String> disabledVersions;
    private boolean suppressDeprecationWarnings;

    @Override
    public void init(FilterConfig config) throws ServletException {
        try {
            // Load build-time configuration
            Properties buildConfig = loadPropertiesFile("rest-api.properties");

            // Load runtime options (overrides build-time config)
            Properties runtimeOptions = loadPropertiesFile("rest-api-option.properties");

            // Merge runtime options into build config
            Properties mergedConfig = new Properties();
            mergedConfig.putAll(buildConfig);
            mergedConfig.putAll(runtimeOptions);

            deprecatedVersion = mergedConfig.getProperty("deprecated.version", "").trim();
            if (deprecatedVersion.isEmpty()) {
                deprecatedVersion = null;
            }

            String buildDisabled = buildConfig.getProperty("disabled.versions", "");
            Set<String> defaultDisabledVersions = parseVersions(buildDisabled);

            // Load runtime configuration
            ServletContext servletContext = config.getServletContext();
            Set<String> runtimeEnabledVersions = Collections.emptySet();

            if (servletContext.getAttribute("engine") instanceof CMSEngine engine) {
                EngineConfig engineConfig = engine.getConfig();

                // Runtime can enable versions from the disabled list
                String runtimeEnabled = engineConfig.getString("rest.api.enabled", "");
                runtimeEnabledVersions = parseVersions(runtimeEnabled);

                // Final disabled = build disabled - runtime enabled
                disabledVersions = new HashSet<>(defaultDisabledVersions);
                disabledVersions.removeAll(runtimeEnabledVersions);

                suppressDeprecationWarnings = engineConfig.getBoolean("rest.api.suppress_deprecation_warnings", false);
            } else {
                // Engine not CMSEngine (e.g., PKIEngine) - use merged config
                String mergedDisabled = mergedConfig.getProperty("disabled.versions", "");
                disabledVersions = parseVersions(mergedDisabled);

                suppressDeprecationWarnings = Boolean.parseBoolean(
                    mergedConfig.getProperty("suppress_deprecation_warnings", "false"));
            }

            logger.info("REST API build-time disabled: {}", defaultDisabledVersions);
            logger.info("REST API runtime enabled: {}", runtimeEnabledVersions);
            logger.info("REST API final disabled: {}", disabledVersions);
            logger.info("REST API deprecated version: {}", deprecatedVersion);

        } catch (Exception e) {
            logger.error("Failed to initialize APIVersionFilter", e);
            deprecatedVersion = null;
            disabledVersions = new HashSet<>();
            suppressDeprecationWarnings = false;
        }
    }

    /**
     * Loads configuration from a properties resource file.
     *
     * @param filename Name of the properties file to load
     * @return Properties object (empty if file not found)
     */
    private Properties loadPropertiesFile(String filename) {
        Properties props = new Properties();
        try (InputStream is = getClass().getClassLoader()
                .getResourceAsStream(filename)) {

            if (is == null) {
                logger.debug("{} not found, skipping", filename);
                return props;
            }

            props.load(is);
            logger.info("Loaded configuration from {}", filename);
        } catch (IOException e) {
            logger.warn("Failed to load {}: {}", filename, e.getMessage());
        }
        return props;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String path = httpRequest.getRequestURI();
        String version = extractVersion(path);

        if (version == null) {
            chain.doFilter(request, response);
            return;
        }

        // Check if disabled
        if (disabledVersions.contains(version)) {
            httpResponse.sendError(HttpServletResponse.SC_NOT_FOUND,
                "REST API " + version + " is not available");
            return;
        }

        // Check if deprecated AND warnings not suppressed
        if (version.equals(deprecatedVersion) && !suppressDeprecationWarnings) {
            httpResponse.setHeader("Deprecation", "true");
        }

        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
        // Nothing to clean up
    }

    /**
     * Extracts the API version from the request path.
     *
     * @param path Request URI path
     * @return API version (e.g., "v1", "v2") or null if no version found
     */
    private String extractVersion(String path) {
        Pattern pattern = Pattern.compile("/(v\\d+)/");
        Matcher matcher = pattern.matcher(path);
        return matcher.find() ? matcher.group(1) : null;
    }

    /**
     * Parses a comma-separated list of versions.
     *
     * @param versions Comma-separated version string
     * @return Set of trimmed, non-empty version strings
     */
    private Set<String> parseVersions(String versions) {
        if (versions == null || versions.trim().isEmpty()) {
            return Collections.emptySet();
        }
        return Arrays.stream(versions.split(","))
            .map(String::trim)
            .filter(s -> !s.isEmpty())
            .collect(Collectors.toSet());
    }
}
