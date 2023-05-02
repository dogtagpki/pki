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
<script src="/pki/js/jquery.js"></script>
<script src="/pki/js/jquery.i18n.properties.js"></script>
<script src="/pki/js/underscore.js"></script>
<script src="/pki/js/backbone.js"></script>
<script src="/pki/js/pki.js"></script>
<script src="/pki/js/pki-banner.js"></script>
<script src="/pki/js/pki-app.js"></script>

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

    var table = $("table[name='apps']");
    var template = $("tr", table).detach();

    var apps = new AppCollection();
    apps.fetch({
        reset: true,
        success: function(collection, response, options) {
            apps.forEach(function(app){
                var name = app.get("name");
                var path = app.get("path");

                var tr = template.clone();
                $("a[name=path]", tr).attr("href", path);
                $("span[name=name]", tr).text(name);
                tr.show();

                table.append(tr);
            });
        },
        error: function(collection, response, options) {
            alert('ERROR: ' + response);
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
    <a href="https://www.dogtagpki.org" title="Visit www.dogtagpki.org for more information about Certificate System products and services"><img src="/pki/images/logo_header.gif" alt="Certificate System" id="myLogo" /></a>
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

<center>

<br>

<table name="apps" border="0" cellspacing="0" cellpadding="0">
<tr style="display: none">
    <td>
        <li><font size=4 face="PrimaSans BT, Verdana, sans-serif">
        <a name="path" href=""><span name="name"></span></a></font>
    </td>
</tr>
</table>

</center>

<div id="footer">
</div>

</body>
</html>
