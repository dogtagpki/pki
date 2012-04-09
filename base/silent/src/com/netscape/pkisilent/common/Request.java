package com.netscape.pkisilent.common;

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

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Vector;

/**
 * CMS Test framework .
 * Submits List,Approve,Reject,cancel requests to agent port
 */

public class Request extends TestClient {

    private String validityperiod;
    private String approveseqnum, type, reqType, reqState, agenttype;
    private int i;

    // Program variables
    private String ACTION_PROCESS_CERT_REQUEST = null;
    private String ACTION_LISTREQUEST = "/queryReq";
    private int reqtype = 1;
    private int seqNumFrom = 1;
    private int maxCount = 50;
    private int validperiod = 180;
    private String cadualcert_name = null;

    private String approveseqnumFrom, approveseqnumTo;
    // Request variables
    private Vector<String> seqNum = new Vector<String>();
    private String AUTH_ID = null;

    // Cert Detail variables

    private String csrRequestorName;
    private String csrRequestorPhone;
    private String csrRequestorEmail;
    private String subject;
    private String subjectdn;
    private String reqStatus;
    @SuppressWarnings("unused")
    private String certType;
    @SuppressWarnings("unused")
    private String requestType;
    private String requestID;
    @SuppressWarnings("unused")
    private String sslclient;
    private String clientcert;
    private String servercert;
    private String emailcert;
    private String objectsigningcert;
    @SuppressWarnings("unused")
    private String sslcacert;
    @SuppressWarnings("unused")
    private String objectsigningcacert;
    @SuppressWarnings("unused")
    private String emailcacert;
    private String sigAlgo;
    @SuppressWarnings("unused")
    private String totalRecord;
    @SuppressWarnings("unused")
    private String validitylength;
    private String trustedManager;

    private int totalNumApproved = 0;

    // Constructors

    /**
     * Constructor . Takes the parameter for Properties file name
     *
     * @param propfileName name of the parameter file.
     */

    public Request(String pfile) {
        propfileName = pfile;
    }

    /**
     * Constructor . Takes the parameter host , port and "angent type - ca/ra"
     *
     * @param hostname.
     * @param port
     * @param agenttype Whether ca or ra agent
     */

    public Request(String h, String p, String at) {
        host = h;
        ports = p;
        agenttype = at;
    }

    /**
     * Constructor . Takes the following parmaters
     *
     * @param hostName .
     * @param port
     * @param adminuid
     * @param adminpwd
     * @param agentcertnickname
     * @param certdb
     * @param tokenpwd
     * @param approveSequncenumber
     * @param ApproveSequenceNumberFrom
     * @param ApproveSequnceNumberTo
     * @param type
     * @param reqtype enrollment/revoked
     * @param requestState complete/pending
     * @param agentType ra/ca
     * @param trustedManager true/false
     */

    public Request(String h, String p, String aid, String apwd, String cname, String cd, String ctpwd, String snum,
            String sfrom, String sto, String ty, String rty, String rstate, String aty, String tm) {
        host = h;
        ports = p;
        adminid = aid;
        adminpwd = apwd;
        certnickname = cname;
        cdir = cd;
        tokenpwd = ctpwd;
        approveseqnum = snum;
        approveseqnumFrom = sfrom;
        if (approveseqnumFrom == null) {
            approveseqnumFrom = "1";
        }

        approveseqnumTo = sto;
        if (approveseqnumTo == null) {
            approveseqnumTo = "100";
        }

        type = ty;
        reqType = rty;
        reqState = rstate;
        agenttype = aty;
        if (agenttype == null) {
            agenttype = "ca";
        }

        trustedManager = tm;
        if (trustedManager.equals("true")) {
            trustedManager = "true";
        } else {
            trustedManager = "false";
        }
        debug = false;

    }

    /**
     * Set Agent Cert nick name
     */
    public void setAgentCertName(String s) {
        certnickname = s;
    }

    /**
     * List all pending enrollment request. Takes parameters fromRequestNumber,toRequestNumber
     *
     * @param fromrequest number
     * @param endrequestnumber.
     * @throws UnsupportedEncodingException
     */

    public Vector<String> ListPendingRequests(String fromRequestNumber, String toRequestNumber) throws UnsupportedEncodingException {
        reqState = "showWaiting";
        reqType = "enrollment";
        approveseqnumFrom = fromRequestNumber;
        approveseqnumTo = toRequestNumber;
        listRequest(approveseqnumFrom, approveseqnumTo);
        return seqNum;
    }

    /**
     * List all pending request. Takes parameters fromRequestNumber,toRequestNumber
     *
     * @param fromrequest number
     * @param endrequestnumber.
     * @throws UnsupportedEncodingException
     */

    public Vector<String> ListAllRequests(String fromRequestNumber, String toRequestNumber) throws UnsupportedEncodingException {
        reqState = "showAll";
        reqType = "enrollment";
        approveseqnumFrom = fromRequestNumber;
        approveseqnumTo = toRequestNumber;
        listRequest(approveseqnumFrom, approveseqnumTo);
        return seqNum;
    }

    /**
     * Approve pending enrollment request. Takes parameters RequestNumber
     *
     * @param request number
     * @throws UnsupportedEncodingException
     */

    public int ApproveRequests(String requestNumber) throws UnsupportedEncodingException {
        reqState = "showWaiting";
        reqType = "enrollment";
        approveseqnum = requestNumber;
        approveseqnumFrom = requestNumber;
        approveseqnumTo = requestNumber;
        if (approveRequest()) {
            System.out.println("Approve Request :" + totalNumApproved);
            return totalNumApproved;
        } else {
            return -1;
        }

    }

    /**
     * Approve profile based pending enrollment request. Takes parameters RequestNumber
     *
     * @param request number
     * @throws UnsupportedEncodingException
     */

    public int ApproveProfileRequests(String RequestNumber) throws UnsupportedEncodingException {

        approveseqnum = RequestNumber;
        approveseqnumFrom = RequestNumber;
        approveseqnumTo = RequestNumber;

        reqtype = 4;
        buildquery();
        if (!Send()) {
            System.out.println("Error: Approving request " + approveseqnum);
            return 0;
        }
        return 1;

    }

    public boolean Approve_cadualcert_Profile_Request(String RequestNumber, String name) throws UnsupportedEncodingException {

        approveseqnum = RequestNumber;
        approveseqnumFrom = RequestNumber;
        approveseqnumTo = RequestNumber;

        cadualcert_name = name;

        // reqtype = 7 means cadualcert profile request
        // this is just a convention that we follow within this file to distinguish
        // bet'n the different requests

        reqtype = 7;

        buildquery();

        if (!Send()) {
            System.out.println("Error: Approving request " + approveseqnum);
            return false;
        }

        return true;

    }

    /**
     * Reject profile based pending enrollment request. Takes parameters RequestNumber
     *
     * @param request number
     * @throws UnsupportedEncodingException
     */

    public int RejectProfileRequests(String RequestNumber) throws UnsupportedEncodingException {

        approveseqnum = RequestNumber;
        approveseqnumFrom = RequestNumber;
        approveseqnumTo = RequestNumber;

        reqtype = 5;
        buildquery();
        if (!Send()) {
            System.out.println("Error: Rejecting request " + approveseqnum);
            return 0;
        }
        return 1;

    }

    /**
     * Cancel profile based pending enrollment request. Takes parameters RequestNumber
     *
     * @param request number
     * @throws UnsupportedEncodingException
     */

    public int CancelProfileRequests(String RequestNumber) throws UnsupportedEncodingException {

        approveseqnum = RequestNumber;
        approveseqnumFrom = RequestNumber;
        approveseqnumTo = RequestNumber;

        reqtype = 6;
        buildquery();
        if (!Send()) {
            System.out.println("Error: canceling request " + approveseqnum);
            return 0;
        }
        return 1;

    }

    // private  methods
    private boolean RetrieveProfileCancel(StringBuffer s) {
        String res = s.toString();
        int ret = 0;

        ret = res.indexOf("requestStatus=");
        String status = res.substring(ret + "requestStatus=".length() + 1,
                res.indexOf(";", ret) - 1);

        if (!status.equals("canceled")) {
            ErrorDetail = res.substring(ret + "errorReason=".length() + 1,
                    res.indexOf(";", ret) - 1);
            return false;
        }

        return true;
    }

    private boolean RetrieveProfileReject(StringBuffer s) {
        String res = s.toString();
        int ret = 0;

        ret = res.indexOf("requestStatus=");
        String status = res.substring(ret + "requestStatus=".length() + 1,
                res.indexOf(";", ret) - 1);

        if (!status.equals("rejected")) {
            ErrorDetail = res.substring(ret + "errorReason=".length() + 1,
                    res.indexOf(";", ret) - 1);
            return false;
        }

        return true;
    }

    private boolean RetrieveProfileApproval(StringBuffer s) {
        String res = s.toString();
        int ret = 0;

        ret = res.indexOf("requestStatus=");
        String status = res.substring(ret + "requestStatus=".length() + 1,
                res.indexOf(";", ret) - 1);

        if (!status.equals("complete")) {
            ErrorDetail = res.substring(ret + "errorReason=".length() + 1,
                    res.indexOf(";", ret) - 1);
            return false;
        }

        return true;

    }

    private boolean RetrieveReq(StringBuffer s) {
        String AUTHID = "header.authorityid = ";
        String seqnum = "record.seqNum";

        String res = s.toString();
        int ret = 0;

        if ((ret = res.indexOf(AUTHID)) > -1) {
            AUTH_ID = res.substring(ret + AUTHID.length() + 1,
                    res.indexOf(";", ret) - 1);
            while (ret > 0) {
                if ((ret = res.indexOf(seqnum, ret)) > -1) {
                    int bi = ret + seqnum.length() + 2;
                    int be = res.indexOf(";", ret) - 1;

                    seqNum.addElement(res.substring(bi, be));
                    ret++;
                }

            }

        }

        ret = res.indexOf("header.totalRecordCount =");
        totalRecord = res.substring(ret + "header.totalRecordCount = ".length(),
                res.indexOf(";", ret));

        return true;

    }

    private boolean RetrieveCertDetails(StringBuffer s) {

        // System.out.println("Debug : Retrieving cert details ");
        String res = s.toString();

        if (debug) {
            System.out.println(res);
        }
        int ret = 0;

        boolean st = false;

        for (int t = 0; t < 25; t++) {
            String cmp = "header.SERVER_ATTRS[" + t + "].name=";

            ret = res.indexOf(cmp);
            if ((res.substring(ret + cmp.length() + 1, res.indexOf(";", ret) - 1)).equals(
                    "requestId")) {
                ret = res.indexOf("header.SERVER_ATTRS[" + t + "].value=");
                requestID = res.substring(
                        ret + "header.SERVER_ATTRS[t].value=".length() + 1,
                        res.indexOf(";", ret) - 1);
            }
            if ((res.substring(ret + cmp.length() + 1, res.indexOf(";", ret) - 1)).equals(
                    "requestStatus")) {
                ret = res.indexOf("header.SERVER_ATTRS[" + t + "].value=");
                reqStatus = res.substring(
                        ret + "header.SERVER_ATTRS[t].value=".length() + 1,
                        res.indexOf(";", ret) - 1);
            }

            if ((res.substring(ret + cmp.length() + 1, res.indexOf(";", ret) - 1)).equals(
                    "requestType")) {
                ret = res.indexOf("header.SERVER_ATTRS[" + t + "].value=");
                requestType = res.substring(
                        ret + "header.SERVER_ATTRS[t].value=".length() + 1,
                        res.indexOf(";", ret) - 1);
            }

        } // end of for loop

        // System.out.println("Debug : Retrieving cert details  Serverattributes ");

        if (requestID.equals(approveseqnum)) {
            st = true;
        }

        if (!st) {
            System.out.println("Error in retrieving the record " + approveseqnum);
            return false;
        }

        // System.out.println("Debug : Retrieving cert details  HTTP parmas  ");

        for (int t = 0; t < 25; t++) {
            String cmp = "header.HTTP_PARAMS[" + t + "].name=";

            ret = res.indexOf(cmp);
            if ((res.substring(ret + cmp.length() + 1, res.indexOf(";", ret) - 1)).equals(
                    "csrRequestorEmail")) {
                ret = res.indexOf("header.HTTP_PARAMS[" + t + "].value=");
                csrRequestorEmail = res.substring(
                        ret + "header.HTTP_PARAMS[t].value=".length() + 1,
                        res.indexOf(";", ret) - 1);
            }
            if ((res.substring(ret + cmp.length() + 1, res.indexOf(";", ret) - 1)).equals(
                    "csrRequestorPhone")) {
                ret = res.indexOf("header.HTTP_PARAMS[" + t + "].value=");
                csrRequestorPhone = res.substring(
                        ret + "header.HTTP_PARAMS[t].value=".length() + 1,
                        res.indexOf(";", ret) - 1);
            }
            if ((res.substring(ret + cmp.length() + 1, res.indexOf(";", ret) - 1)).equals(
                    "csrRequestorName")) {
                ret = res.indexOf("header.HTTP_PARAMS[" + t + "].value=");
                csrRequestorName = res.substring(
                        ret + "header.HTTP_PARAMS[t].value=".length() + 1,
                        res.indexOf(";", ret) - 1);
            }

            if ((res.substring(ret + cmp.length() + 1, res.indexOf(";", ret) - 1)).equals(
                    "subject")) {
                ret = res.indexOf("header.HTTP_PARAMS[" + t + "].value=");
                subjectdn = res.substring(
                        ret + "header.HTTP_PARAMS[t].value=".length() + 1,
                        res.indexOf(";", ret) - 1);
            }

        } // end of for loop

        // System.out.println("Debug : Retrieving cert details");

        ret = res.indexOf("header.subject =");
        if (ret > 0) {
            subject = res.substring(ret + "header.subject = ".length() + 1,
                    res.indexOf(";", ret) - 1);
        }
        // System.out.println("Debug : Retrieving cert details ");

        sslclient =
                clientcert =
                        servercert =
                                emailcert = objectsigningcert = sslcacert = objectsigningcacert = emailcacert = "false";
        ret = res.indexOf("header.sslclient =");
        if (ret > 0) {
            sslclient = res.substring(ret + "header.sslclient = ".length() + 1,
                    res.indexOf(";", ret) - 1);
        }
        // System.out.println("Debug : Retrieving cert details ");

        ret = res.indexOf("header.ext_ssl_client =");
        if (ret > 0) {
            clientcert = res.substring(
                    ret + "header.ext_ssl_client = ".length() + 1,
                    res.indexOf(";", ret) - 1);
        }
        // System.out.println("Debug : Retrieving cert details ");

        ret = res.indexOf("header.ext_email =");
        if (ret > 0) {
            emailcert = res.substring(ret + "header.ext_email = ".length() + 1,
                    res.indexOf(";", ret) - 1);
        }
        // System.out.println("Debug : Retrieving cert details ");

        ret = res.indexOf("header.ext_ssl_server =");
        if (ret > 0) {
            servercert = res.substring(
                    ret + "header.ext_ssl_server = ".length() + 1,
                    res.indexOf(";", ret) - 1);
        }

        // System.out.println("Debug : Retrieving cert details ");

        ret = res.indexOf("header.ext_object_signing =");
        if (ret > 0) {
            objectsigningcert = res.substring(
                    ret + "header.ext_object_signing = ".length() + 1,
                    res.indexOf(";", ret) - 1);
        }

        // System.out.println("Debug : Retrieving cert details ");

        ret = res.indexOf("header.ext_ssl_ca =");
        if (ret > 0) {
            sslcacert = res.substring(ret + "header.ext_ssl_ca = ".length() + 1,
                    res.indexOf(";", ret) - 1);
        }

        // System.out.println("Debug : Retrieving cert details ");

        if (ret > 0) {
            ret = res.indexOf("header.ext_object_signing_ca=");
        }
        objectsigningcacert = res.substring(
                ret + "header.ext_object_signing_ca = ".length() + 1,
                res.indexOf(";", ret) - 1);

        // System.out.println("Debug : Retrieving cert details ");

        ret = res.indexOf("header.ext_email_ca =");
        if (ret > 0) {
            emailcacert = res.substring(
                    ret + "header.ext_email_ca = ".length() + 1,
                    res.indexOf(";", ret) - 1);
        }

        // System.out.println("Debug : Retrieving cert details ");

        ret = res.indexOf("header.certType =");
        if (ret > 0) {
            certType = res.substring(ret + "header.certType = ".length() + 1,
                    res.indexOf(";", ret) - 1);
        }
        // System.out.println("Debug : Retrieving cert details ");

        ret = res.indexOf("header.signatureAlgorithmName =");
        if (ret > 0) {
            sigAlgo = res.substring(
                    ret + "header.signatureAlgorithmName = ".length() + 1,
                    res.indexOf(";", ret) - 1);
        }

        ret = res.indexOf("header.validityLength =");
        if (ret > 0) {
            validitylength = res.substring(
                    ret + "header.validityLength = ".length() + 1,
                    res.indexOf(";", ret) - 1);
        }

        return true;

    }

    private boolean approveRequestStatus(StringBuffer s) {

        String res = s.toString();

        if (debug) {
            System.out.println(res);
        }

        // Find th Server_ATTRS paramteter value of reqStatus

        int i = 1;
        int ret;

        for (int t = 0; t < 25; t++) {
            String cmp = "header.SERVER_ATTRS[" + t + "].name=";

            ret = res.indexOf(cmp);
            if ((res.substring(ret + cmp.length() + 1, res.indexOf(";", ret) - 1)).equals(
                    "requestStatus")) {
                i = t;
                break;
            }

        }

        String req = "header.SERVER_ATTRS[" + i + "].value=";

        ret = res.indexOf(req);
        reqStatus = res.substring(ret + req.length() + 1,
                res.indexOf(";", ret) - 1);

        if (reqStatus != null) {
            reqStatus.toLowerCase();
            if (reqStatus.equals("complete")) {
                return true;
            } else {
                return false;
            }
        }

        return false;

    }

    private boolean Send() {
        debug = true;
        boolean st = false;

        try {
            // Covert the string port to int port

            Integer x = new Integer(ports);

            port = x.intValue();

            Con2Agent con = new Con2Agent(host, port, certnickname, tokenpwd,
                    cdir);

            con.setQueryString(query);
            con.setActionURL(ACTION_STRING);
            con.Send();
            StringBuffer s = new StringBuffer();

            s = con.getPage();

            if (debug) {
                System.out.println(s.toString());
            }
            switch (reqtype) {
            case 1:
                st = RetrieveReq(s);
                break;

            case 2:
                st = RetrieveCertDetails(s);
                break;

            case 3:
                st = approveRequestStatus(s);
                break;

            case 4:
                st = RetrieveProfileApproval(s);
                break;

            case 5:
                st = RetrieveProfileReject(s);
                break;

            case 6:
                st = RetrieveProfileCancel(s);
                break;

            case 7:
                st = RetrieveProfileApproval(s);
                break;

            default:
                System.out.println("reqtype not recognized");
            }
        } catch (Exception e) {
            System.err.println("exception: in Send routine" + e);
            return false;
        }

        return st;
    }

    private void buildquery() throws UnsupportedEncodingException {

        if (reqtype == 1) { // req type = list
            ACTION_STRING = "/" + agenttype + ACTION_LISTREQUEST;
            query = "seqNumFrom=" + seqNumFrom;
            query += "&maxCount=" + maxCount;
            query += "&reqType=" + reqType;
            query += "&reqState=" + reqState;

        }

        if (reqtype == 2) { // get cert details
            ACTION_PROCESS_CERT_REQUEST = "/" + AUTH_ID + "/processCertReq";
            ACTION_STRING = ACTION_PROCESS_CERT_REQUEST;
            query = "seqNum=" + approveseqnum;

        }

        if (reqtype == 3) { // aaprove cert

            if (validityperiod != null) {
                Integer x = new Integer(validityperiod);

                validperiod = x.intValue();
            } else {
                validperiod = 180;
            }

            ACTION_PROCESS_CERT_REQUEST = "/" + AUTH_ID + "/processCertReq";
            ACTION_STRING = ACTION_PROCESS_CERT_REQUEST;
            query = "seqNum=" + approveseqnum;
            query += "&toDo=accept";
            if (subjectdn != null) {
                query += "&subject=" + URLEncoder.encode(subjectdn, "UTF-8");
            } else if (subject != null) {
                query += "&subject=" + URLEncoder.encode(subject, "UTF-8");
            }

            if (csrRequestorName != null) {
                query += "&csrRequestorName=" + csrRequestorName;
            }
            if (csrRequestorPhone != null) {
                query += "&csrRequestorPhone=" + csrRequestorPhone;
            }

            if (csrRequestorEmail != null) {
                query += "&csrRequestorEmail=" + csrRequestorEmail;
            }
            if (sigAlgo != null) {
                query += "&signatureAlgorithm=" + sigAlgo;
            }
            query += "&grantUID=u" + approveseqnum;

            GregorianCalendar begin = new GregorianCalendar();
            GregorianCalendar end = new GregorianCalendar();

            end.add(GregorianCalendar.DATE, validperiod);
            Date begindate = begin.getTime();
            Date enddate = end.getTime();

            query += "&notValidBefore=" + begindate.getTime() / 1000;
            query += "&notValidAfter=" + enddate.getTime() / 1000;

            if (clientcert.equals("true")) {
                query += "&certTypeSSLClient=" + clientcert;
            }

            if (servercert.equals("true")) {
                query += "&certTypeSSLServer=" + servercert;
            }

            if (emailcert.equals("true")) {
                query += "&certTypeEmail=" + emailcert;
            }

            if (objectsigningcert.equals("true")) {
                query += "&certTypeObjSigning=" + objectsigningcert;
            }

            query += "&grantTrustedManagerPrivilege=" + trustedManager;

        }

        if ((reqtype == 4) || (reqtype == 5) || (reqtype == 6)) { // profile based cert request

            if (validityperiod != null) {
                Integer x = new Integer(validityperiod);

                validperiod = x.intValue();
            } else {
                validperiod = 180;
            }

            ACTION_PROCESS_CERT_REQUEST = "/" + agenttype + "/profileProcess";
            ACTION_STRING = ACTION_PROCESS_CERT_REQUEST;
            query = "requestId=" + approveseqnum;
            query += "&name="
                    + URLEncoder.encode(
                            "UID=test,E=test,CN=test,OU=netscape,O=aol", "UTF-8");
            query += "&keyUsageCritical=true";
            query += "&keyUsageDigitalSignature=true";
            query += "&keyUsageNonRepudiation=true";
            query += "&keyUsageKeyEncipherment=true";
            query += "&keyUsageDataEncipherment=false";
            query += "&keyUsageKeyAgreement=false";
            query += "&keyUsageKeyCertSign=false";
            query += "&keyUsageCrlSign=false";
            query += "&keyUsageEncipherOnly=false";
            query += "&keyUsageDecipherOnly=false";

            query += "&nsCertCritical=false";
            query += "&nsCertSSLClient=true";

            query += "&nsCertSSLServer=false";
            query += "&nsCertEmail=true";
            query += "&nsCertObjectSigning=false";
            query += "&nsCertSSLCA=false";
            query += "&nsCertEmailCA=false";
            query += "&nsCertObjectSigningCA=false";

            query += "&subAltNameExtCritical=false";
            query += "&subjAltNames=RFC822Name:"
                    + URLEncoder.encode(" thomasknscp@aol.com", "UTF-8");
            query += "&signingAlg=MD5withRSA";

            query += "&submit=submit";

            GregorianCalendar begin = new GregorianCalendar();
            GregorianCalendar end = new GregorianCalendar();

            end.add(GregorianCalendar.DATE, validperiod);
            // Date begindate = begin.getTime();
            // Date enddate = end.getTime();
            String nb = begin.get(Calendar.YEAR) + "-"
                    + begin.get(Calendar.MONTH) + "-" + begin.get(Calendar.DATE)
                    + " " + begin.get(Calendar.HOUR) + ":"
                    + begin.get(Calendar.MINUTE) + ":"
                    + begin.get(Calendar.SECOND);

            String nat = end.get(Calendar.YEAR) + "-" + end.get(Calendar.MONTH)
                    + "-" + end.get(Calendar.DATE) + " "
                    + end.get(Calendar.HOUR) + ":" + end.get(Calendar.MINUTE)
                    + ":" + end.get(Calendar.SECOND);

            query += "&notBefore=" + nb;
            query += "&notAfter=" + nat;

            query += "&authInfoAccessCritical=false";
            query += "&authInfoAccessGeneralNames=";
            query += "&exKeyUsageOIDs=" + "1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4";

        }

        if (reqtype == 4) {
            query += "&op=approve";
        }

        if (reqtype == 5) {
            query += "&op=reject";
        }

        if (reqtype == 6) {
            query += "&op=cancel";
        }

        if (reqtype == 7) {
            // cadualcert profile approval
            ACTION_STRING = "/" + "ca" + "/profileProcess";

            GregorianCalendar begin = new GregorianCalendar();
            GregorianCalendar end = new GregorianCalendar();

            end.add(GregorianCalendar.DATE, validperiod);

            String nb = begin.get(Calendar.YEAR) + "-"
                    + begin.get(Calendar.MONTH) + "-" + begin.get(Calendar.DATE)
                    + " " + begin.get(Calendar.HOUR) + ":"
                    + begin.get(Calendar.MINUTE) + ":"
                    + begin.get(Calendar.SECOND);

            String nat = end.get(Calendar.YEAR) + "-" + end.get(Calendar.MONTH)
                    + "-" + end.get(Calendar.DATE) + " "
                    + end.get(Calendar.HOUR) + ":" + end.get(Calendar.MINUTE)
                    + ":" + end.get(Calendar.SECOND);

            query = "requestId=" + approveseqnum + "&name="
                    + URLEncoder.encode(cadualcert_name, "UTF-8") + "&notBefore=" + nb
                    + "&notAfter=" + nat + "&authInfoAccessCritical=false"
                    + "&authInfoAccessGeneralNames=" + "&keyUsageCritical=true"
                    + "&keyUsageDigitalSignature=false"
                    + "&keyUsageNonRepudiation=false"
                    + "&keyUsageKeyEncipherment=true"
                    + "&keyUsageDataEncipherment=false"
                    + "&keyUsageKeyAgreement=false"
                    + "&keyUsageKeyCertSign=false" + "&keyUsageCrlSign=false"
                    + "&keyUsageEncipherOnly=false"
                    + "&keyUsageDecipherOnly=false" + /* -- For Older CMS 6.x servers use these
                                                      "&nsCertCritical=false" +
                                                      "&nsCertSSLClient=true" +
                                                      "&nsCertSSLServer=false" +
                                                      "&nsCertEmail=true" +
                                                      "&nsCertObjectSigning=false" +
                                                      "&nsCertSSLCA=false" +
                                                      "&nsCertEmailCA=false" +
                                                      "&nsCertObjectSigningCA=false" +
                                                      "&subjAltNameExtCritical=false" +
                                                      "&subjAltNames=RFC822Name: null" +
                                                      "&signingAlg=MD5withRSA" +
                                                      */// For newer CS 7.x servers use these
                    "&exKeyUsageCritical=false"
                    + "&exKeyUsageOIDs=1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4"
                    + "&subjAltNameExtCritical=false"
                    + "&subjAltNames=RFC822Name: null"
                    + "&signingAlg=SHA1withRSA" + "&requestNotes="
                    + "&op=approve" + "&submit=submit";

        }

    }

    private void readProperties() {

        // Read the properties file and assign values to variables .
        try {
            getProperties(propfileName);
        } catch (Exception e) {
            System.out.println(
                    "exception reading Properties File " + e.getMessage());
        }

        // Read the properties file
        host = props.getProperty("enroll.host");
        ports = props.getProperty("enroll.port");
        adminid = props.getProperty("enroll.adminid");
        adminpwd = props.getProperty("enroll.adminpwd");
        certnickname = props.getProperty("enroll.nickname");
        cdir = props.getProperty("enroll.certdir");
        tokenpwd = props.getProperty("enroll.certtokenpwd");
        approveseqnum = props.getProperty("enroll.seqnum");
        if (approveseqnum == null) {
            System.out.println("Seq num is null");
        }

        approveseqnumFrom = props.getProperty("enroll.seqnumFrom");
        if (approveseqnumFrom == null) {
            approveseqnumFrom = "1";
        }

        approveseqnumTo = props.getProperty("enroll.seqnumTo");
        if (approveseqnumTo == null) {
            approveseqnumTo = "100";
        }
        validityperiod = props.getProperty("enroll.validperiod");
        type = props.getProperty("enroll.type");
        reqType = props.getProperty("enroll.reqtype");
        reqState = props.getProperty("enroll.reqstate");
        agenttype = props.getProperty("enroll.agenttype");
        if (agenttype == null) {
            agenttype = "ca";
        }

        trustedManager = props.getProperty("enroll.trust");
        if (trustedManager.equals("true")) {
            trustedManager = "true";
        } else {
            trustedManager = "false";
        }

        String de = props.getProperty("enroll.debug");

        if (de == null) {
            debug = false;
        } else if (de.equals("true")) {
            debug = true;
        } else {
            debug = false;
        }

    }

    private boolean listRequest(String from, String To) throws UnsupportedEncodingException {

        Integer x = new Integer(from);

        seqNumFrom = x.intValue();

        Integer y = new Integer(To);

        if ((y.intValue() - seqNumFrom) > 50) {
            maxCount = 50;
        } else {
            maxCount = y.intValue() - x.intValue();
        }
        if (maxCount == 0) {
            maxCount = 1;
        }

        reqtype = 1;
        buildquery();
        return (Send());
    }

    private boolean approveRequest() throws UnsupportedEncodingException {

        boolean st = true;

        listRequest(approveseqnumFrom, approveseqnumTo);

        if (seqNum.isEmpty()) {
            System.out.println("No Requests for approval");
            return false;
        }

        if (approveseqnum.length() > 0) {
            if (seqNum.contains(approveseqnum)) {
                seqNum.removeAllElements();
                seqNum.addElement(approveseqnum);
            } else {
                System.out.println(
                        " Seq num " + approveseqnum + " already approved ");
                return false;
            }
        } else {
            System.out.println(
                    " Seq num not specified . Approving all pending request From : "
                            + approveseqnumFrom + " To : " + approveseqnumTo);
        }

        boolean flag = true;

        Integer y = new Integer(approveseqnumTo);
        int torequest = y.intValue();

        while (flag) {

            i = 0;
            while (i < seqNum.size()) {

                approveseqnum = (seqNum.elementAt(i)).toString();
                // Get request details
                reqtype = 2;
                buildquery();
                if (!Send()) {
                    System.out.println("Error : Getting Request details ");
                    i++;
                    continue;
                }

                if (debug) {
                    System.out.println(
                            csrRequestorName + " " + csrRequestorPhone + " "
                                    + csrRequestorEmail + " " + requestID + " "
                                    + subject);
                }
                // Now for pending status -  approve the request
                reqtype = 3;
                buildquery();
                if (!Send()) {
                    System.out.println(
                            "Error: Approving request " + approveseqnum);
                    i++;
                    continue;
                }
                System.out.println("Request " + approveseqnum + " is approved ");
                totalNumApproved++;
                i++;
            }
            Integer x = new Integer(approveseqnum);

            if (x.intValue() >= torequest) {
                flag = false;
            } else {
                listRequest(approveseqnum, approveseqnumTo);
            }

        }
        return st;
    }

    /**
     * Use this method when you need to use properties file.
     * @throws UnsupportedEncodingException
     */

    public int processRequest() throws UnsupportedEncodingException {
        if (propfileName != null) {
            readProperties();
        }

        if (approveseqnum.length() > 0) {
            approveseqnumFrom = approveseqnum;
            approveseqnumTo = approveseqnum;
        }

        type = type.toLowerCase();
        if (type.equals("approve")) {
            if (approveRequest()) {
                System.out.println("Approve Request :" + totalNumApproved);
                return totalNumApproved;
            } else {
                return -1;
            }

        }

        if (type.equals("list")) {

            if (listRequest(approveseqnumFrom, approveseqnumTo)) {
                System.out.println("List Request : " + seqNum.size());
                if (seqNum.size() > 0) {
                    return seqNum.size();
                } else {
                    return 0;
                }
            } else {
                return -1;
            }

        }

        return -1;
    }

    public static void main(String args[]) {
        // Exit Status - (0) for error
        // - any number > 0 Pass
        int st = 0;

        if (args.length < 1) {
            System.out.println("Usage : propertiesfile");
            System.exit(0);
        }

        Request t = new Request(args[0]);

        try {
            st = t.processRequest();
        } catch (UnsupportedEncodingException e) {
            System.out.println(e);
            e.printStackTrace();
        }
        if (st == -1) {
            System.exit(0);
        } else {
            System.exit(st);
        }

    }// end of function main

} // end of class

