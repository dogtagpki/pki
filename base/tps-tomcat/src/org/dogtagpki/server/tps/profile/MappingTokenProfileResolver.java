package org.dogtagpki.server.tps.profile;

import java.lang.Integer;
import org.dogtagpki.server.tps.engine.TPSEngine;
import org.dogtagpki.tps.main.TPSException;
import org.dogtagpki.tps.msg.EndOp.TPSStatus;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;

/**
 * MappingTokenProfileResolver is a profile resolver plugin that calculates
 * token type by sorting through a list of filters in mapping
 */
public class MappingTokenProfileResolver extends BaseTokenProfileResolver {

    public MappingTokenProfileResolver() {
    }

    public String getTokenType(TokenProfileParams pParam)
            throws TPSException {

        String tokenType = null;
        String mappingOrder = null;
        int major_version = 0;
        int minor_version = 0;
        String cuid = null;
        // String msn = null;
        String eTokenType = null;
        String eTokenATR = null;

        CMS.debug("MappingTokenProfileResolver.getTokenType: starts");

        major_version = pParam.getInt(TokenProfileParams.PROFILE_PARAM_MAJOR_VERSION);
        CMS.debug("MappingTokenProfileResolver: param major_version =" + major_version);

        minor_version = pParam.getInt(TokenProfileParams.PROFILE_PARAM_MINOR_VERSION);
        CMS.debug("MappingTokenProfileResolver: param minor_version =" + minor_version);

        cuid =  pParam.getString(TokenProfileParams.PROFILE_PARAM_CUID);
        // msn = (String) pParam.get(TokenProfileParams.PROFILE_PARAM_MSN);
        // they don't necessarily have extension
        try {
            eTokenType = pParam.getString(TokenProfileParams.PROFILE_PARAM_EXT_TOKEN_TYPE);
            eTokenATR =  pParam.getString(TokenProfileParams.PROFILE_PARAM_EXT_TOKEN_ATR);
        } catch (TPSException e) {
            CMS.debug("MappingTokenProfileResolver: OK to not have extension. Continue.");
        }

        CMS.debug("MappingTokenProfileResolver: params retrieved.");

        String configName = prefix + "." + TPSEngine.CFG_PROFILE_MAPPING_ORDER;

        try {
            CMS.debug("MappingTokenProfileResolver: getting mapping order:" +
                    configName);
            mappingOrder = configStore.getString(configName);
        } catch (EPropertyNotFound e) {
            CMS.debug("MappingTokenProfileResolver: exception:" + e);
            throw new TPSException(
                    "MappingTokenProfileResolver.getTokenType: Token Type configuration incorrect! Mising mapping order!",
                    TPSStatus.STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND);

        } catch (EBaseException e1) {
            //The whole feature won't work if this is wrong.
            CMS.debug("MappingTokenProfileResolver: exception:" + e1);
            throw new TPSException(
                    "MappingTokenProfileResolver.getTokenType: Internal error obtaining config value.!",
                    TPSStatus.STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND);
        }

        String targetTokenType = null;

        for (String mappingId : mappingOrder.split(",")) {

            CMS.debug("MappingTokenProfileResolver.getTokenType:  mapping: " + mappingId);

            String mappingConfigName = prefix + ".mapping." + mappingId + ".target.tokenType";

            CMS.debug("MappingTokenProfileResolver.getTokenType:  mappingConfigName: " + mappingConfigName);

            //We need this to exist.
            try {
                targetTokenType = configStore.getString(mappingConfigName);
            } catch (EPropertyNotFound e) {
                throw new TPSException(
                        "MappingTokenProfileResolver.getTokenType: Token Type configuration incorrect! No target token type config value found! Config: "
                                + mappingConfigName,
                        TPSStatus.STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND);

            } catch (EBaseException e) {
                throw new TPSException(
                        "MappingTokenProfileResolver.getTokenType: Internal error obtaining config value. Config: "
                                + mappingConfigName,
                        TPSStatus.STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND);
            }

            mappingConfigName = prefix + ".mapping." + mappingId + ".filter.tokenType";

            CMS.debug("MappingTokenProfileResolver.getTokenType:  mappingConfigName: " + mappingConfigName);

            //For this and remaining cases, it is not automatically an error if we don't get anything back
            // from the config.
            try {
                tokenType = configStore.getString(mappingConfigName, null);
            } catch (EBaseException e) {
                throw new TPSException(
                        "MappingTokenProfileResolver.getTokenType: Internal error obtaining config value. Config: "
                                + mappingConfigName,
                        TPSStatus.STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND);

            }

            CMS.debug("MappingTokenProfileResolver.getTokenType:  targetTokenType: " + targetTokenType);

            if (tokenType != null && tokenType.length() > 0) {

                if (eTokenType == null) {
                    continue;
                }

                //String eTokenType = extensions.get("tokenType");
                //if (eTokenType == null) {
                //    continue;
                //}

                if (!eTokenType.equals(tokenType)) {
                    continue;
                }
            }

            mappingConfigName = prefix + ".mapping." + mappingId + ".filter.tokenATR";

            CMS.debug("MappingTokenProfileResolver.getTokenType:  mappingConfigName: " + mappingConfigName);

            String tokenATR = null;

            try {
                tokenATR = configStore.getString(mappingConfigName, null);
            } catch (EBaseException e) {
                throw new TPSException(
                        "MappingTokenProfileResolver.getTokenType: Internal error obtaining config value. Config: "
                                + mappingConfigName,
                        TPSStatus.STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND);
            }

            CMS.debug("MappingTokenProfileResolver.getTokenType:  tokenATR: " + tokenATR);

            if (tokenATR != null && tokenATR.length() > 0) {
                if (eTokenATR == null) {
                    continue;
                }

                //String eTokenATR = extensions.get("tokenATR");

                //if (eTokenATR == null) {
                //    continue;
                //}

                if (!eTokenATR.equals(tokenATR)) {
                    continue;
                }

            }

            mappingConfigName = prefix + ".mapping." + mappingId + ".filter.tokenCUID.start";

            CMS.debug("MappingTokenProfileResolver.getTokenType:  mappingConfigName: " + mappingConfigName);

            String tokenCUIDStart = null;

            try {
                tokenCUIDStart = configStore.getString(mappingConfigName, null);

            } catch (EBaseException e) {
                throw new TPSException(
                        "MappingTokenProfileResolver.getTokenType: Internal error obtaining config value. Config: "
                                + mappingConfigName,
                        TPSStatus.STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND);
            }

            CMS.debug("MappingTokenProfileResolver.getTokenType:  tokenCUIDStart: " + tokenCUIDStart);

            if (tokenCUIDStart != null && tokenCUIDStart.length() > 0) {
                if (cuid == null) {
                    continue;
                }

                if (tokenCUIDStart.length() != 20) {
                    continue;
                }

                if (cuid.compareTo(tokenCUIDStart) < 0) {
                    continue;
                }

            }

            mappingConfigName = prefix + ".mapping." + mappingId + ".filter.tokenCUID.end";

            CMS.debug("MappingTokenProfileResolver.getTokenType:  mappingConfigName: " + mappingConfigName);

            String tokenCUIDEnd = null;
            try {
                tokenCUIDEnd = configStore.getString(mappingConfigName, null);
            } catch (EBaseException e) {
                throw new TPSException(
                        "MappingTokenProfileResolver.getTokenType: Internal error obtaining config value. Config: "
                                + mappingConfigName,
                        TPSStatus.STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND);
            }

            CMS.debug("MappingTokenProfileResolver.getTokenType:  tokenCUIDEnd: " + tokenCUIDEnd);

            if (tokenCUIDEnd != null && tokenCUIDEnd.length() > 0) {
                if (cuid == null) {
                    continue;
                }

                if (tokenCUIDEnd.length() != 20) {
                    continue;
                }

                if (cuid.compareTo(tokenCUIDEnd) > 0) {
                    continue;
                }

            }

            mappingConfigName = prefix + ".mapping." + mappingId + ".filter.appletMajorVersion";

            CMS.debug("MappingTokenProfileResolver.getTokenType:  mappingConfigName: " + mappingConfigName);

            String majorVersion = null;
            String minorVersion = null;

            try {
                majorVersion = configStore.getString(mappingConfigName, null);
            } catch (EBaseException e) {
                throw new TPSException(
                        "MappingTokenProfileResolver.getTokenType: Internal error obtaining config value. Config: "
                                + mappingConfigName,
                        TPSStatus.STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND);
            }

            CMS.debug("MappingTokenProfileResolver.getTokenType:  majorVersion: " + majorVersion);
            if (majorVersion != null && majorVersion.length() > 0) {

                int major = Integer.parseInt(majorVersion);

                if (major != major_version) {
                    continue;
                }
            }

            mappingConfigName = prefix + ".mapping." + mappingId + ".filter.appletMinorVersion";

            CMS.debug("MappingTokenProfileResolver.getTokenType:  mappingConfigName: " + mappingConfigName);

            try {
                minorVersion = configStore.getString(mappingConfigName, null);
            } catch (EBaseException e) {
                throw new TPSException(
                        "MappingTokenProfileResolver.getTokenType: Internal error obtaining config value. Config: "
                                + mappingConfigName,
                        TPSStatus.STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND);
            }
            CMS.debug("MappingTokenProfileResolver.getTokenType:  minorVersion " + minorVersion);

            if (minorVersion != null && minorVersion.length() > 0) {

                int minor = Integer.parseInt(minorVersion);

                if (minor != minor_version) {
                    continue;
                }
            }

            //if we make it this far, we have a token type
            CMS.debug("MappingTokenProfileResolver.getTokenType: Selected Token type: " + targetTokenType);
            break;
        }

        if (targetTokenType == null) {
            CMS.debug("MappingTokenProfileResolver.getTokenType: end found: " + targetTokenType);
            throw new TPSException("MappingTokenProfileResolver.getTokenType: Can't find token type!",
                    TPSStatus.STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND);
        }

        return targetTokenType;

    }

}
