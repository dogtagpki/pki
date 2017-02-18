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
<link href="/pki/css/patternfly.css" rel="stylesheet" media="screen, print">
<script type="text/javascript" language="JavaScript" src="/pki/js/jquery.js"></script>
<script type="text/javascript" language="JavaScript" src="/pki/js/jquery.i18n.properties.js"></script>
<script type="text/javascript" language="JavaScript" src="/pki/js/bootstrap.js"></script>

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


<div class="col-lg-7">
<p>
The <span class="message" name="title">Certificate System</span> is an enterprise-class open source Certificate Authority (CA).
It is a full-featured system, and has been hardened by real-world deployments.
It supports all aspects of certificate lifecycle management, including key archival, OCSP and smartcard management, and much more.
</p>

<p>
<b><font size="+2"><a name="enter" href="/pki/ui/">Enter</a></font></b>
</p>

</div>

<div id="footer">
</div>

</body>
</html>
