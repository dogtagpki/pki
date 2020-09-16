<!--
Copyright Red Hat, Inc.

SPDX-License-Identifier: GPL-2.0-or-later
-->
<html>
<head>
    <title>ACME Responder</title>
    <link rel="stylesheet" href="css/patternfly-4.35.2.css">
    <script src="js/jquery-3.5.1.js"></script>

    <script>
$(function() {

    // replace ACME_URL with actual ACME URL
    var i = window.location.href.lastIndexOf('/');
    var acme_url = window.location.href.substring(0, i);

    $("pre").each(function() {
        var content = this.innerText;
        this.innerText = content.replace("ACME_URL", acme_url);
    });

    // display actual ACME metadata
    $.get({
        url: "directory",
        dataType: "json"

    }).done(function(data, textStatus, jqXHR) {
        $("a[name='termsOfService']").text(data.meta.termsOfService);
        $("a[name='termsOfService']").attr("href", data.meta.termsOfService);
        $("a[name='website']").text(data.meta.website);
        $("a[name='website']").attr("href", data.meta.website);
        $("span[name='caaIdentities']").text(data.meta.caaIdentities.join(", "));
        $("span[name='externalAccountRequired']").text(data.meta.externalAccountRequired);

    }).fail(function(jqXHR, textStatus, errorThrown) {
        alert('ERROR: ' + response);
    });
});
    </script>

</head>
<body>

<div class="pf-c-page">

  <header class="pf-c-page__header">
    <div class="pf-c-page__header-brand">
      <a class="pf-c-page__header-brand-link">ACME Responder</a>
    </div>
  </header>

  <main class="pf-c-page__main" tabindex="-1">
    <section class="pf-c-page__main-section pf-m-light">
      <div class="pf-c-content">
<h1>ACME Responder</h1>

<h2>Metadata</h2>

<ul>
<li><b>Terms of service:</b> <a href="" name="termsOfService"></a></li>
<li><b>Website:</b> <a name="website"></a></li>
<li><b>CAA identities:</b> <span name="caaIdentities"></span></li>
<li><b>External account required:</b> <span name="externalAccountRequired"></span></li>
</ul>

<h2>Account Management</h2>

To create an ACME account:

<pre>
$ certbot register \
    --server ACME_URL/directory \
    -m &lt;email address&gt; \
    --agree-tos
</pre>

To update an ACME account:

<pre>
$ certbot update_account \
    --server ACME_URL/directory \
    -m &lt;new email address&gt;
</pre>

To deactivate an ACME account:

<pre>
$ certbot unregister \
    --server ACME_URL/directory
</pre>

<h2>Certificate Enrollment</h2>

To request a certificate with automatic http-01 validation:

<pre>
$ certbot certonly --standalone \
    --server ACME_URL/directory \
    --preferred-challenges http \
    -d server.example.com
</pre>

To request a certificate with manual dns-01 validation:

<pre>
$ certbot certonly --manual \
    --server ACME_URL/directory \
    --preferred-challenges dns \
    -d server.example.com
</pre>

<h2>Certificate Revocation</h2>

To revoke a certificate owned by the ACME account:

<pre>
$ certbot revoke \
    --server ACME_URL/directory \
    --cert-path /etc/letsencrypt/live/server.example.com/fullchain.pem
</pre>

To revoke a certificate associated with a private key:

<pre>
$ certbot revoke \
    --server ACME_URL/directory \
    --cert-path /etc/letsencrypt/live/server.example.com/fullchain.pem \
    --key-path /etc/letsencrypt/live/server.example.com/privkey.pem
</pre>
      </div>
    </section>

  </main>
</div>

</body>
</html>
