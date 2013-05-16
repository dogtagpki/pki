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
<title>Certificate System</title>
<meta http-equiv=Content-Type content="text/html; charset=UTF-8">
<link rel="shortcut icon" href="/pki/images/favicon.ico" />
<link rel="stylesheet" href="/pki/css/pki-base.css" type="text/css" />
</head>
<body bgcolor="#FFFFFF" link="#666699" vlink="#666699" alink="#333366">

<div id="header">
    <a href="http://pki.fedoraproject.org/" title="Visit pki.fedoraproject.org for more information about Dogtag products and services"><img src="/pki/images/logo_header.gif" alt="Dogtag" id="myLogo" /></a>
    <div id="headertitle">
    <a href="/" title="Dogtag Network homepage">Dogtag<sup><font size="-2">&reg;</font></sup> Certificate System</a>
    </div>
    <div id="account">
          <dl><dt><span></span></dt><dd></dd></dl>
    </div>
</div>

<div id="mainNavOuter">
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


<center>

<%
    ServletContext caContext = getServletContext().getContext("/ca");
    String caName = caContext.getServletContextName();
    String caPath = caContext.getContextPath();
    if (!"".equals(caPath)) {
%>
<p>
<font size="+1" face="PrimaSans BT, Verdana, Arial, Helvetica, sans-serif">
<%= caName %>
</font>
</p>

<table border="0" cellspacing="0" cellpadding="0">
<tr valign="TOP">
    <td>
        <li><font size=4 face="PrimaSans BT, Verdana, sans-serif">
        <a href="/ca/ee/ca">End Users Services</a></font>
    </td>
</tr>
<%
        if (request.isSecure()) {
%>
<tr valign="TOP">
    <td>
        <li><font size=4 face="PrimaSans BT, Verdana, sans-serif">
        <a href="/ca/agent/ca">Agent Services</a></font>
    </td>
</tr>
<tr valign="TOP">
    <td>
        <li><font size=4 face="PrimaSans BT, Verdana, sans-serif">
        <a href="/ca/services">Admin Services</a></font>
    </td>
</tr>
<%
        }
%>
</table>

<br>

<%
    }

    ServletContext kraContext = getServletContext().getContext("/kra");
    String kraName = kraContext.getServletContextName();
    String kraPath = kraContext.getContextPath();
    if (!"".equals(kraPath) && request.isSecure()) {
%>
<p>
<font size="+1" face="PrimaSans BT, Verdana, Arial, Helvetica, sans-serif">
<%= kraName %>
</font>
</p>

<table border="0" cellspacing="0" cellpadding="0">
<tr valign="TOP">
    <td>
        <li><font size=4 face="PrimaSans BT, Verdana, sans-serif">
        <a href="/kra/agent/kra">Agent Services</a></font>
    </td>
</tr>
<tr valign="TOP">
    <td>
        <li><font size=4 face="PrimaSans BT, Verdana, sans-serif">
        <a href="/kra/services">Admin Services</a></font>
    </td>
</tr>
</table>

<br>

<%
    }

    ServletContext ocspContext = getServletContext().getContext("/ocsp");
    String ocspName = ocspContext.getServletContextName();
    String ocspPath = ocspContext.getContextPath();
    if (!"".equals(ocspPath) && request.isSecure()) {
%>
<p>
<font size="+1" face="PrimaSans BT, Verdana, Arial, Helvetica, sans-serif">
<%= ocspName %>
</font>
</p>

<table border="0" cellspacing="0" cellpadding="0">
<tr valign="TOP">
    <td>
        <li><font size=4 face="PrimaSans BT, Verdana, sans-serif">
        <a href="/ocsp/agent/ocsp">Agent Services</a></font>
    </td>
</tr>
<tr valign="TOP">
    <td>
        <li><font size=4 face="PrimaSans BT, Verdana, sans-serif">
        <a href="/ocsp/services">Admin Services</a></font>
    </td>
</tr>
</table>

<br>

<%
    }

    ServletContext tksContext = getServletContext().getContext("/tks");
    String tksName = tksContext.getServletContextName();
    String tksPath = tksContext.getContextPath();
    if (!"".equals(tksPath) && request.isSecure()) {
%>
<p>
<font size="+1" face="PrimaSans BT, Verdana, Arial, Helvetica, sans-serif">
<%= tksName %>
</font>
</p>

<table border="0" cellspacing="0" cellpadding="0">
<tr valign="TOP">
    <td>
        <li><font size=4 face="PrimaSans BT, Verdana, sans-serif">
        <a href="/tks/agent/tks">Agent Services</a></font>
    </td>
</tr>
<tr valign="TOP">
    <td>
        <li><font size=4 face="PrimaSans BT, Verdana, sans-serif">
        <a href="/tks/services">Admin Services</a></font>
    </td>
</tr>
</table>

<br>

<%
    }

    ServletContext tpsContext = getServletContext().getContext("/tps");
    String tpsName = tpsContext.getServletContextName();
    String tpsPath = tpsContext.getContextPath();
    if (!"".equals(tpsPath) && request.isSecure()) {
%>
<p>
<font size="+1" face="PrimaSans BT, Verdana, Arial, Helvetica, sans-serif">
<%= tpsName %>
</font>
</p>

<table border="0" cellspacing="0" cellpadding="0">
<tr valign="TOP">
    <td>
        <li><font size=4 face="PrimaSans BT, Verdana, sans-serif">
        <a href="/tps/agent/tps">Agent Services</a></font>
    </td>
</tr>
<tr valign="TOP">
    <td>
        <li><font size=4 face="PrimaSans BT, Verdana, sans-serif">
        <a href="/tps/services">Admin Services</a></font>
    </td>
</tr>
</table>

<br>

<%
    }
%>

</center>

<div id="footer">
</div>

</body>
</html>
