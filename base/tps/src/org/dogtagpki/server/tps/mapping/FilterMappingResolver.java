package org.dogtagpki.server.tps.mapping;

import org.dogtagpki.server.tps.engine.TPSEngine;
import org.dogtagpki.tps.main.TPSException;
import org.dogtagpki.tps.msg.EndOpMsg.TPSStatus;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;

/**
 * FilterMappingResolver is a mapping resolver plugin that calculates
 * result by sorting through a list of filters in mapping
 *
 * @author cfu
 */
public class FilterMappingResolver extends BaseMappingResolver {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(FilterMappingResolver.class);

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

        logger.debug(method + " starts");

        major_version = mappingParams.getInt(FilterMappingParams.FILTER_PARAM_MAJOR_VERSION);
        logger.debug(method + " param major_version =" + major_version);

        minor_version = mappingParams.getInt(FilterMappingParams.FILTER_PARAM_MINOR_VERSION);
        logger.debug(method + " param minor_version =" + minor_version);

        cuid =  mappingParams.getString(FilterMappingParams.FILTER_PARAM_CUID);
        logger.debug(method + " param cuid =" + cuid);
        // msn = (String) mappingParams.get(FilterMappingParams.FILTER_PARAM_MSN);

        // they don't necessarily have extension
        try {
            extTokenType = mappingParams.getString(FilterMappingParams.FILTER_PARAM_EXT_TOKEN_TYPE);
        } catch (TPSException e) {
            logger.warn(method + " OK to not have tokenType extension. Continue: " + e.getMessage(), e);
        }
        try {
            extTokenATR = mappingParams.getString(FilterMappingParams.FILTER_PARAM_EXT_TOKEN_ATR);
        } catch (TPSException e) {
            logger.warn(method + " OK to not have tokenATR extension. Continue: " + e.getMessage(), e);
        }
        try {
            extKeySet = mappingParams.getString(FilterMappingParams.FILTER_PARAM_EXT_KEY_SET);
        } catch (TPSException e) {
            logger.warn(method + " OK to not have keySet extension. Continue: " + e.getMessage(), e);
        }


        logger.debug(method + " mapping params retrieved.");

        String configName = prefix + "." + TPSEngine.CFG_PROFILE_MAPPING_ORDER;

        try {
            logger.debug(method + " getting mapping order:" +
                    configName);
            mappingOrder = configStore.getString(configName);
        } catch (EPropertyNotFound e) {
            logger.error(method + " exception:" + e.getMessage(), e);
            throw new TPSException(
                    method + " configuration incorrect! Mising mapping order:" + configName,
                    TPSStatus.STATUS_ERROR_MAPPING_RESOLVER_FAILED);

        } catch (EBaseException e1) {
            //The whole feature won't work if this is wrong.
            logger.error(method + " exception:" + e1.getMessage(), e1);
            throw new TPSException(
                    method + " Internal error obtaining config value:" + configName,
                    TPSStatus.STATUS_ERROR_MAPPING_RESOLVER_FAILED);
        }


        for (String mappingId : mappingOrder.split(",")) {

            logger.debug(method + "  mapping: " + mappingId);

            String mappingConfigName = prefix + ".mapping." + mappingId + ".target." + nameToMap;

            logger.debug(method + "  mappingConfigName: " + mappingConfigName);

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
            logger.debug(method + "  targetMappedName: " + targetMappedName);

            /*
             * For this and remaining names, it is not automatically an error if we don't get anything back
             * from the config.  It is just not considered.
             */
            mappingConfigName = prefix + ".mapping." + mappingId + ".filter.tokenType";
            logger.debug(method + "  mappingConfigName: " + mappingConfigName);

            try {
                tokenType = configStore.getString(mappingConfigName, null);
            } catch (EBaseException e) {
                throw new TPSException(
                        method + " Internal error obtaining config value. Config: "
                                + mappingConfigName,
                        TPSStatus.STATUS_ERROR_MAPPING_RESOLVER_FAILED);
            }
            logger.debug(method + " tokenType: " + tokenType);

            if (tokenType != null && tokenType.length() > 0) {

                if (extTokenType == null) {
                    continue;
                }

                if (!extTokenType.equals(tokenType)) {
                    continue;
                }
            }

            mappingConfigName = prefix + ".mapping." + mappingId + ".filter.keySet";
            logger.debug(method + " mappingConfigName: " + mappingConfigName);

            try {
                keySet = configStore.getString(mappingConfigName, null);
            } catch (EBaseException e) {
                throw new TPSException(
                        method + " Internal error obtaining config value. Config: "
                                + mappingConfigName,
                        TPSStatus.STATUS_ERROR_MAPPING_RESOLVER_FAILED);
            }

            logger.debug(method + " keySet: " + keySet);

            if (keySet != null && keySet.length() > 0) {

                if (extKeySet == null) {
                    continue;
                }

                if (!extKeySet.equals(keySet)) {
                    continue;
                }
            }

            mappingConfigName = prefix + ".mapping." + mappingId + ".filter.tokenATR";
            logger.debug(method + " mappingConfigName: " + mappingConfigName);

            String tokenATR = null;

            try {
                tokenATR = configStore.getString(mappingConfigName, null);
            } catch (EBaseException e) {
                throw new TPSException(
                        method + " Internal error obtaining config value. Config: "
                                + mappingConfigName,
                        TPSStatus.STATUS_ERROR_MAPPING_RESOLVER_FAILED);
            }

            logger.debug(method + " tokenATR: " + tokenATR);

            if (tokenATR != null && tokenATR.length() > 0) {
                if (extTokenATR == null) {
                    continue;
                }

                if (!extTokenATR.equals(tokenATR)) {
                    continue;
                }
            }

            mappingConfigName = prefix + ".mapping." + mappingId + ".filter.tokenCUID.start";
            logger.debug(method + " mappingConfigName: " + mappingConfigName);

            String tokenCUIDStart = null;

            try {
                tokenCUIDStart = configStore.getString(mappingConfigName, null);

            } catch (EBaseException e) {
                throw new TPSException(
                        method + " Internal error obtaining config value. Config: "
                                + mappingConfigName,
                        TPSStatus.STATUS_ERROR_MAPPING_RESOLVER_FAILED);
            }

            logger.debug(method + " tokenCUIDStart: " + tokenCUIDStart);

            if (tokenCUIDStart != null && tokenCUIDStart.length() > 0) {
                if (cuid == null) {
                    continue;
                }

                if (tokenCUIDStart.length() != 20) {
                    continue;
                }

                if (cuid.compareToIgnoreCase(tokenCUIDStart) < 0) {
                    logger.debug(method + " cuid < tokenCUIDStart ... out of range");
                    continue;
                }

            }

            mappingConfigName = prefix + ".mapping." + mappingId + ".filter.tokenCUID.end";
            logger.debug(method + " mappingConfigName: " + mappingConfigName);

            String tokenCUIDEnd = null;
            try {
                tokenCUIDEnd = configStore.getString(mappingConfigName, null);
            } catch (EBaseException e) {
                throw new TPSException(
                        method + " Internal error obtaining config value. Config: "
                                + mappingConfigName,
                        TPSStatus.STATUS_ERROR_MAPPING_RESOLVER_FAILED);
            }

            logger.debug(method + " tokenCUIDEnd: " + tokenCUIDEnd);

            if (tokenCUIDEnd != null && tokenCUIDEnd.length() > 0) {
                if (cuid == null) {
                    continue;
                }

                if (tokenCUIDEnd.length() != 20) {
                    continue;
                }

                if (cuid.compareToIgnoreCase(tokenCUIDEnd) > 0) {
                    logger.debug(method + " cuid > tokenCUIDEnd ... out of range");
                    continue;
                }

            }

            mappingConfigName = prefix + ".mapping." + mappingId + ".filter.appletMajorVersion";
            logger.debug(method + " mappingConfigName: " + mappingConfigName);

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

            logger.debug(method + " majorVersion: " + majorVersion);
            if (majorVersion != null && majorVersion.length() > 0) {

                int major = Integer.parseInt(majorVersion);

                if (major != major_version) {
                    continue;
                }
            }

            mappingConfigName = prefix + ".mapping." + mappingId + ".filter.appletMinorVersion";
            logger.debug(method + "  mappingConfigName: " + mappingConfigName);

            try {
                minorVersion = configStore.getString(mappingConfigName, null);
            } catch (EBaseException e) {
                throw new TPSException(
                        method + " Internal error obtaining config value. Config: "
                                + mappingConfigName,
                        TPSStatus.STATUS_ERROR_MAPPING_RESOLVER_FAILED);
            }
            logger.debug(method + " minorVersion " + minorVersion);

            if (minorVersion != null && minorVersion.length() > 0) {

                int minor = Integer.parseInt(minorVersion);

                if (minor != minor_version) {
                    continue;
                }
            }

            //if we make it this far, we have a mapped name
            selectedMappedName = targetMappedName;
            logger.debug(method + " Selected mapped name: " + selectedMappedName);
            break;
        }

        if (selectedMappedName == null) {
            logger.error(method + " ends, found: " + selectedMappedName);
            throw new TPSException(method + " Can't map to target name!",
                    TPSStatus.STATUS_ERROR_MAPPING_RESOLVER_FAILED);
        }

        return selectedMappedName;

    }

}
