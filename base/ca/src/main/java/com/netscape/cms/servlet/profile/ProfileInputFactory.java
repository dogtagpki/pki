package com.netscape.cms.servlet.profile;

import java.util.Enumeration;
import java.util.Locale;

import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.ProfileAttribute;
import com.netscape.certsrv.profile.ProfileInput;
import com.netscape.cmscore.base.ArgBlock;
import com.netscape.cmscore.request.Request;

public class ProfileInputFactory {

    public static ProfileInput create(
            com.netscape.cms.profile.common.ProfileInput input,
            Request request,
            Locale locale) throws EProfileException  {

        ProfileInput ret = new ProfileInput();
        ret.setName(input.getName(locale));
        ret.setClassId(input.getClass().getSimpleName());

        Enumeration<String> names = input.getValueNames();
        while (names.hasMoreElements()) {
            String name = names.nextElement();
            String value = input.getValue(name, locale, request);
            if (value != null) {
                ret.addAttribute(new ProfileAttribute(name, value, null));
            }
        }

        return ret;
    }

    public static ProfileInput create(
            com.netscape.cms.profile.common.ProfileInput input,
            ArgBlock params,
            Locale locale) throws EProfileException {

        ProfileInput ret = new ProfileInput();
        ret.setName(input.getName(locale));
        ret.setClassId(input.getClass().getSimpleName());

        Enumeration<String> names = input.getValueNames();
        while (names.hasMoreElements()) {
            String name = names.nextElement();
            String value = params.getValueAsString(name, null);
            if (value != null) {
                ret.addAttribute(new ProfileAttribute(name, value, null));
            }
        }

        return ret;
    }
}
