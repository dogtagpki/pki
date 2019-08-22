package com.netscape.cms.servlet.profile;

import java.util.Enumeration;
import java.util.Locale;

import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IProfileInput;
import com.netscape.certsrv.profile.ProfileAttribute;
import com.netscape.certsrv.profile.ProfileInput;
import com.netscape.certsrv.request.IRequest;

public class ProfileInputFactory {

    public static ProfileInput create(IProfileInput input, IRequest request, Locale locale) throws EProfileException  {
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

    public static ProfileInput create(IProfileInput input, IArgBlock params, Locale locale) throws EProfileException {
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
