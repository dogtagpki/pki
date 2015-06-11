<!-- --- BEGIN COPYRIGHT BLOCK ---
     This program is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published by
     the Free Software Foundation; version 2 of the License.

     This program is distributed in the hope that it will be useful,
     but WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
     GNU General Public License for more details.

     You should have received a copy of the GNU General Public License along
     with this program; if not, write to the Free Software Foundation, Inc.,
     51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

     Copyright (C) 2012 Red Hat, Inc.
     All rights reserved.
     --- END COPYRIGHT BLOCK --- -->
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<script type="text/javascript" language="JavaScript" src="/pki/js/jquery.js"></script>
<script type="text/javascript" language="JavaScript" src="/pki/js/jquery.i18n.properties.js"></script>

<script type="text/javascript" language="JavaScript">
$(function() {
    $.i18n.properties({
        name: 'pki',
        language: ' ', // suppress potential 404's due to .i18n.browserLang()
        path: '/pki/',
        mode: 'map',
        callback: function() {
            var key;
            for (key in $.i18n.map) {
                var message = $.i18n.prop(key);
                $('span.message[name='+key+']').html(message);
            }
        }
    });
});
</script>

<title>Certificate System</title>
<meta http-equiv=Content-Type content="text/html; charset=UTF-8">
<link rel="shortcut icon" href="/pki/images/favicon.ico" />
<link rel="stylesheet" href="/pki/css/pki-base.css" type="text/css" />
</head>
<body bgcolor="#FFFFFF" link="#666699" vlink="#666699" alink="#333366">

<div id="header">
    <span class="message" name="logo">
    <a href="http://pki.fedoraproject.org/" title="Visit pki.fedoraproject.org for more information about Certificate System products and services"><img src="/pki/images/logo_header.gif" alt="Certificate System" id="myLogo" /></a>
    </span>
    <div id="headertitle">
    <span class="message" name="title">
    <a href="/" title=Certificate System">Certificate System</a>
    </span>
    </div>
    <div id="account">
          <dl><dt><span></span></dt><dd></dd></dl>
    </div>
</div>

<div id="mainNavOuter" class="pki-ee-theme">
<div id="mainNav">
<div id="mainNavInner">

</div><!-- end mainNavInner -->
</div><!-- end mainNav -->
</div><!-- end mainNavOuter -->


<div id="bar">

<div id="systembar">
<div id="systembarinner">

<div>
  -
</div>


</div>
</div>

</div>

<script>
if (typeof(crypto) != "undefined" && typeof(crypto.version) != "undefined") {
} else {
    document.write('<p> <font color="red"> Warning: This version of Firefox no longer supports the crypto web object used to generate and archive keys from the broswer. Although Certificate System will continue to work, some of the functionality may be no longer supported. </font> </p>');
    document.write('<br>');
}
</script>


<center>

<br>

<table border="0" cellspacing="0" cellpadding="0">
<tr valign="TOP">
    <td>
<%
    ServletContext caContext = getServletContext().getContext("/ca");
    if (caContext != null) {
        String caName = caContext.getServletContextName();
        String caPath = caContext.getContextPath();
        if (!"".equals(caPath)) {
%>
        <li><font size=4 face="PrimaSans BT, Verdana, sans-serif">
        <a href="/ca"><%= caName %></a></font>
<%
        }
    }

    ServletContext kraContext = getServletContext().getContext("/kra");
    if (kraContext != null) {
        String kraName = kraContext.getServletContextName();
        String kraPath = kraContext.getContextPath();
        if (!"".equals(kraPath) && request.isSecure()) {
%>
        <li><font size=4 face="PrimaSans BT, Verdana, sans-serif">
        <a href="/kra"><%= kraName %></a></font>
<%
        }
    }

    ServletContext ocspContext = getServletContext().getContext("/ocsp");
    if (ocspContext != null) {
        String ocspName = ocspContext.getServletContextName();
        String ocspPath = ocspContext.getContextPath();
        if (!"".equals(ocspPath) && request.isSecure()) {
%>
        <li><font size=4 face="PrimaSans BT, Verdana, sans-serif">
        <a href="/ocsp"><%= ocspName %></a></font>
<%
        }
    }

    ServletContext tksContext = getServletContext().getContext("/tks");
    if (tksContext != null) {
        String tksName = tksContext.getServletContextName();
        String tksPath = tksContext.getContextPath();
        if (!"".equals(tksPath) && request.isSecure()) {
%>
        <li><font size=4 face="PrimaSans BT, Verdana, sans-serif">
        <a href="/tks"><%= tksName %></a></font>
<%
        }
    }

    ServletContext tpsContext = getServletContext().getContext("/tps");
    if (tpsContext != null) {
        String tpsName = tpsContext.getServletContextName();
        String tpsPath = tpsContext.getContextPath();
        if (!"".equals(tpsPath) && request.isSecure()) {
%>
        <li><font size=4 face="PrimaSans BT, Verdana, sans-serif">
        <a href="/tps/"><%= tpsName %></a></font>
<%
        }
    }
%>
    </td>
</tr>
</table>

</center>

<div id="footer">
</div>

</body>
</html>
