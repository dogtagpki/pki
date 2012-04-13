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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.servlet.csadmin;

public class Cert {
    private String mNickname = "";
    private String mTokenname = "";
    private String mRequest = "";
    private String mCert = "";
    private String mType = ""; // "selfsign," "local," or "remote"
    private String mDN = "";
    private String mCertTag = "";
    private String mCertpp = "";
    private String mUserFriendlyName = "";
    private String mKeyOption = "";
    private String mCustomKeysize = "";
    private String mCustomCurvename = "";
    private boolean mEnable = true;
    private boolean mSigningRequired = false;
    private String mSubsystem = "";
    private String certChain = "";

    public Cert(String tokenName, String nickName, String certTag) {
        mTokenname = tokenName;
        mNickname = nickName;
        mCertTag = certTag;
    }

    public void setEnable(boolean enable) {
        mEnable = enable;
    }

    public boolean isEnable() {
        return mEnable;
    }

    public void setSigningRequired(boolean required) {
        mSigningRequired = required;
    }

    public boolean isSigningRequired() {
        return mSigningRequired;
    }

    public void setNickname(String s) {
        mNickname = s;
    }

    public String getNickname() {
        return mNickname;
    }

    public void setSubsystem(String s) {
        mSubsystem = s;
    }

    public String getSubsystem() {
        return mSubsystem;
    }

    public String getUserFriendlyName() {
        return mUserFriendlyName;
    }

    public void setUserFriendlyName(String name) {
        mUserFriendlyName = name;
    }

    public String getTokenname() {
        return mTokenname;
    }

    public String getRequest() {
        return mRequest;
    }

    public void setRequest(String req) {
        mRequest = req;
    }

    public String getEscapedCert() {
        return escapeForHTML(mCert);
    }

    public String getCert() {
        return mCert;
    }

    public void setCert(String cert) {
        mCert = cert;
    }

    public String getType() {
        return mType;
    }

    public void setType(String type) {
        mType = type;
    }

    public String escapeForHTML(String s) {
        s = s.replaceAll("\"", "&quot;");
        return s;
    }

    public String getEscapedDN() {
        // Need to escape "
        return escapeForHTML(mDN);
    }

    public String getDN() {
        return mDN;
    }

    public void setDN(String dn) {
        mDN = dn;
    }

    public String getCertTag() {
        return mCertTag;
    }

    public String getEscapedCertpp() {
        return escapeForHTML(mCertpp);
    }

    public String getCertpp() {
        return mCertpp;
    }

    public void setCertpp(String pp) {
        mCertpp = pp;
    }

    public String getKeyOption() {
        return mKeyOption;
    }

    /*
     * "default" or "custom"
     */
    public void setKeyOption(String option) {
        mKeyOption = option;
    }

    public boolean useDefaultKey() {
        return (mKeyOption.equals("default"));
    }

    public String getCustomKeysize() {
        return mCustomKeysize;
    }

    public void setCustomKeysize(String size) {
        mCustomKeysize = size;
    }

    public String getCustomCurvename() {
        return mCustomCurvename;
    }

    public void setCustomCurvename(String curve) {
        mCustomCurvename = curve;
    }

    public String getCertChain() {
        return certChain;
    }

    public void setCertChain(String certChain) {
        this.certChain = certChain;
    }
}
