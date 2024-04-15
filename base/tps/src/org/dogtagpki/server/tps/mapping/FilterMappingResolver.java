package org.dogtagpki.server.tps.mapping;

import org.dogtagpki.server.tps.engine.TPSEngine;
import org.dogtagpki.tps.main.TPSException;
import org.dogtagpki.tps.msg.EndOpMsg.TPSStatus;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;

/**
 * FilterMappingResolver is a mapping resolver plugin that calculates
 * result by sorting through a list of filters in mapping
 *
 * @author cfu
 */
public class FilterMappingResolver extends BaseMappingResolver {

    public FilterMappingResolver() {
    }

    public String getResolvedMapping(FilterMappingParams mappingParams)
            throws TPSException {
        //map tokenType by default
        return getResolvedMapping(mappingParams, "tokenType");
    }

    // from TPS: RA_Processor::ProcessMappingFilter
    public String getResolvedMapping(FilterMappingParams mappingParams, String nameToMap)
            throws TPSException {
        // ** G&D 256 Key Rollover Support **
        // call the overloaded method, passing null for symKeySize 
        return getResolvedMapping(mappingParams, nameToMap, null);
    }
    
    // ** G&D 256 Key Rollover Support **
    // Overload the method with the symKeySize parameter
    public String getResolvedMapping(FilterMappingParams mappingParams, String nameToMap, Integer symKeySize)
            throws TPSException {
        String method = "FilterMappingResolver.getResolvedMapping for "+ nameToMap + ": ";
        String tokenType = null;
        String keySet = null;

        String mappingOrder = null;
        int major_version = 0;
        int minor_version = 0;
        String cuid = null;
        // String msn = null;
        String extTokenType = null;
        String extTokenATR = null;
        String extKeySet = null;

        String targetMappedName = null;
        String selectedMappedName = null;

        CMS.debug(method + " starts");

        major_version = mappingParams.getInt(FilterMappingParams.FILTER_PARAM_MAJOR_VERSION);
        CMS.debug(method + " param major_version =" + major_version);

        minor_version = mappingParams.getInt(FilterMappingParams.FILTER_PARAM_MINOR_VERSION);
        CMS.debug(method + " param minor_version =" + minor_version);

        cuid =  mappingParams.getString(FilterMappingParams.FILTER_PARAM_CUID);
        CMS.debug(method + " param cuid =" + cuid);
        // msn = (String) mappingParams.get(FilterMappingParams.FILTER_PARAM_MSN);

        // they don't necessarily have extension
        try {
            extTokenType = mappingParams.getString(FilterMappingParams.FILTER_PARAM_EXT_TOKEN_TYPE);
        } catch (TPSException e) {
            CMS.debug(method + " OK to not have tokenType extension. Continue.");
        }
        try {
            extTokenATR = mappingParams.getString(FilterMappingParams.FILTER_PARAM_EXT_TOKEN_ATR);
        } catch (TPSException e) {
            CMS.debug(method + " OK to not have tokenATR extension. Continue.");
        }
        try {
            extKeySet = mappingParams.getString(FilterMappingParams.FILTER_PARAM_EXT_KEY_SET);
        } catch (TPSException e) {
            CMS.debug(method + " OK to not have keySet extension. Continue.");
        }


        CMS.debug(method + " mapping params retrieved.");

        String configName = prefix + "." + TPSEngine.CFG_PROFILE_MAPPING_ORDER;

        try {
            CMS.debug(method + " getting mapping order:" +
                    configName);
            mappingOrder = configStore.getString(configName);
        } catch (EPropertyNotFound e) {
            CMS.debug(method + " exception:" + e);
            throw new TPSException(
                    method + " configuration incorrect! Mising mapping order:" + configName,
                    TPSStatus.STATUS_ERROR_MAPPING_RESOLVER_FAILED);

        } catch (EBaseException e1) {
            //The whole feature won't work if this is wrong.
            CMS.debug(method + " exception:" + e1);
            throw new TPSException(
                    method + " Internal error obtaining config value:" + configName,
                    TPSStatus.STATUS_ERROR_MAPPING_RESOLVER_FAILED);
        }


        for (String mappingId : mappingOrder.split(",")) {

            CMS.debug(method + "  mapping: " + mappingId);

            String mappingConfigName = prefix + ".mapping." + mappingId + ".target." + nameToMap;

            CMS.debug(method + "  mappingConfigName: " + mappingConfigName);

            //We need this to exist.
            try {
                targetMappedName = configStore.getString(mappingConfigName);
            } catch (EPropertyNotFound e) {
                throw new TPSException(
                        method + " Mapping Resolver configuration incorrect! No target name config value found! Config: "
                                + mappingConfigName,
                        TPSStatus.STATUS_ERROR_MAPPING_RESOLVER_FAILED);

            } catch (EBaseException e) {
                throw new TPSException(
                        method + " Internal error obtaining config value. Config: "
                                + mappingConfigName,
                        TPSStatus.STATUS_ERROR_MAPPING_RESOLVER_FAILED);
            }
            CMS.debug(method + "  targetMappedName: " + targetMappedName);

            /*
             * For this and remaining names, it is not automatically an error if we don't get anything back
             * from the config.  It is just not considered.
             */
            mappingConfigName = prefix + ".mapping." + mappingId + ".filter.tokenType";
            CMS.debug(method + "  mappingConfigName: " + mappingConfigName);

            try {
                tokenType = configStore.getString(mappingConfigName, null);
            } catch (EBaseException e) {
                throw new TPSException(
                        method + " Internal error obtaining config value. Config: "
                                + mappingConfigName,
                        TPSStatus.STATUS_ERROR_MAPPING_RESOLVER_FAILED);
            }
            CMS.debug(method + " tokenType: " + tokenType);

            if (tokenType != null && tokenType.length() > 0) {

                if (extTokenType == null) {
                    continue;
                }

                if (!extTokenType.equals(tokenType)) {
                    continue;
                }
            }

            mappingConfigName = prefix + ".mapping." + mappingId + ".filter.keySet";
            CMS.debug(method + " mappingConfigName: " + mappingConfigName);

            try {
                keySet = configStore.getString(mappingConfigName, null);
            } catch (EBaseException e) {
                throw new TPSException(
                        method + " Internal error obtaining config value. Config: "
                                + mappingConfigName,
                        TPSStatus.STATUS_ERROR_MAPPING_RESOLVER_FAILED);
            }

            CMS.debug(method + " keySet: " + keySet);

            if (keySet != null && keySet.length() > 0) {

                if (extKeySet == null) {
                    continue;
                }

                if (!extKeySet.equals(keySet)) {
                    continue;
                }
            }

            mappingConfigName = prefix + ".mapping." + mappingId + ".filter.tokenATR";
            CMS.debug(method + " mappingConfigName: " + mappingConfigName);

            String tokenATR = null;

            try {
                tokenATR = configStore.getString(mappingConfigName, null);
            } catch (EBaseException e) {
                throw new TPSException(
                        method + " Internal error obtaining config value. Config: "
                                + mappingConfigName,
                        TPSStatus.STATUS_ERROR_MAPPING_RESOLVER_FAILED);
            }

            CMS.debug(method + " tokenATR: " + tokenATR);

            if (tokenATR != null && tokenATR.length() > 0) {
                if (extTokenATR == null) {
                    continue;
                }

                if (!extTokenATR.equals(tokenATR)) {
                    continue;
                }
            }

            mappingConfigName = prefix + ".mapping." + mappingId + ".filter.tokenCUID.start";
            CMS.debug(method + " mappingConfigName: " + mappingConfigName);

            String tokenCUIDStart = null;

            try {
                tokenCUIDStart = configStore.getString(mappingConfigName, null);

            } catch (EBaseException e) {
                throw new TPSException(
                        method + " Internal error obtaining config value. Config: "
                                + mappingConfigName,
                        TPSStatus.STATUS_ERROR_MAPPING_RESOLVER_FAILED);
            }

            CMS.debug(method + " tokenCUIDStart: " + tokenCUIDStart);

            if (tokenCUIDStart != null && tokenCUIDStart.length() > 0) {
                if (cuid == null) {
                    continue;
                }

                if (tokenCUIDStart.length() != 20) {
                    continue;
                }

                if (cuid.compareToIgnoreCase(tokenCUIDStart) < 0) {
                    CMS.debug(method + " cuid < tokenCUIDStart ... out of range");
                    continue;
                }

            }

            mappingConfigName = prefix + ".mapping." + mappingId + ".filter.tokenCUID.end";
            CMS.debug(method + " mappingConfigName: " + mappingConfigName);

            String tokenCUIDEnd = null;
            try {
                tokenCUIDEnd = configStore.getString(mappingConfigName, null);
            } catch (EBaseException e) {
                throw new TPSException(
                        method + " Internal error obtaining config value. Config: "
                                + mappingConfigName,
                        TPSStatus.STATUS_ERROR_MAPPING_RESOLVER_FAILED);
            }

            CMS.debug(method + " tokenCUIDEnd: " + tokenCUIDEnd);

            if (tokenCUIDEnd != null && tokenCUIDEnd.length() > 0) {
                if (cuid == null) {
                    continue;
                }

                if (tokenCUIDEnd.length() != 20) {
                    continue;
                }

                if (cuid.compareToIgnoreCase(tokenCUIDEnd) > 0) {
                    CMS.debug(method + " cuid > tokenCUIDEnd ... out of range");
                    continue;
                }

            }

            mappingConfigName = prefix + ".mapping." + mappingId + ".filter.appletMajorVersion";
            CMS.debug(method + " mappingConfigName: " + mappingConfigName);

            String majorVersion = null;
            String minorVersion = null;

            try {
                majorVersion = configStore.getString(mappingConfigName, null);
            } catch (EBaseException e) {
                throw new TPSException(
                        method + " Internal error obtaining config value. Config: "
                                + mappingConfigName,
                        TPSStatus.STATUS_ERROR_MAPPING_RESOLVER_FAILED);
            }

            CMS.debug(method + " majorVersion: " + majorVersion);
            if (majorVersion != null && majorVersion.length() > 0) {

                int major = Integer.parseInt(majorVersion);

                if (major != major_version) {
                    continue;
                }
            }

            mappingConfigName = prefix + ".mapping." + mappingId + ".filter.appletMinorVersion";
            CMS.debug(method + "  mappingConfigName: " + mappingConfigName);

            try {
                minorVersion = configStore.getString(mappingConfigName, null);
            } catch (EBaseException e) {
                throw new TPSException(
                        method + " Internal error obtaining config value. Config: "
                                + mappingConfigName,
                        TPSStatus.STATUS_ERROR_MAPPING_RESOLVER_FAILED);
            }
            CMS.debug(method + " minorVersion " + minorVersion);

            if (minorVersion != null && minorVersion.length() > 0) {

                int minor = Integer.parseInt(minorVersion);

                if (minor != minor_version) {
                    continue;
                }
            }
            
            // ** G&D 256 Key Rollover Support **
            // G&D SPC03 tokens have same token range but different AES key sizes (128 and 256)
            // If symKeySize is passed in, and if ...filter.symKeySize is configured, check
            // whether the two values match.
            // Skip symKeySize comparison if the parameter is not passed in
            if (symKeySize != null) {
                mappingConfigName = prefix + ".mapping." + mappingId + ".filter.symKeySize";
                CMS.debug(method + "  mappingConfigName: " + mappingConfigName);
                String configSymKeySize = null;
                try {
                    configSymKeySize = configStore.getString(mappingConfigName, null);
                } catch (EBaseException e) {
                    throw new TPSException(
                            method + " Internal error obtaining config value. Config: "
                                    + mappingConfigName,
                            TPSStatus.STATUS_ERROR_MAPPING_RESOLVER_FAILED);
                }
                
                // skip symKeySize comparison if not configured
                if (configSymKeySize != null && configSymKeySize.length() > 0) {
                    CMS.debug(method + " cuid: " + cuid + ": comparing symKeySize: configured: " + configSymKeySize + " expected: " + symKeySize);
                    if (Integer.parseInt(configSymKeySize) != symKeySize.intValue()) {
                        continue;
                    }
                }    
            }
            
            //if we make it this far, we have a mapped name
            selectedMappedName = targetMappedName;
            CMS.debug(method + " Selected mapped name: " + selectedMappedName);
            break;
        }

        if (selectedMappedName == null) {
            CMS.debug(method + " ends, found: " + selectedMappedName);
            throw new TPSException(method + " Can't map to target name!",
                    TPSStatus.STATUS_ERROR_MAPPING_RESOLVER_FAILED);
        }

        return selectedMappedName;

    }
}
