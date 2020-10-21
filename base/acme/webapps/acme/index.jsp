<!--
Copyright Red Hat, Inc.

SPDX-License-Identifier: GPL-2.0-or-later
-->
<html>
<head>
    <title>ACME Responder</title>
    <link rel="stylesheet" href="css/patternfly-4.35.2.css">
    <script src="js/jquery-3.5.1.js"></script>
    <script src="js/pki-acme.js"></script>
    <script>
$(function() {
    updateHomePage();
    updateBaseURL();
    updateLoginInfo();

    activateProfileMenu();
});
    </script>
</head>
<body>

<div class="pf-c-page">

  <header class="pf-c-page__header">
    <div class="pf-c-page__header-brand">
      <a class="pf-c-page__header-brand-link">ACME Responder</a>
    </div>
    <div class="pf-c-page__header-tools">
      <div class="pf-c-dropdown" style="--pf-global--BorderWidth--sm: 0px;">
        <button id="profile-menu" class="pf-c-dropdown__toggle" type="button" aria-expanded="false">
          <span class="pf-c-dropdown__toggle-image">
            <img class="pf-c-avatar" alt="Avatar image" src="css/assets/images/img_avatar.svg">
          </span>
          <span id="profile-fullName" class="pf-c-dropdown__toggle-text"></span>
          <span class="pf-c-dropdown__toggle-icon">
            <i class="fas fa-caret-down" aria-hidden="true"></i>
          </span>
        </button>
        <ul aria-labelledby="profile-menu" class="pf-c-dropdown__menu pf-m-align-right" hidden="hidden">
          <li class="login-menu" hidden="hidden">
            <a class="pf-c-dropdown__menu-item" href="#">Log In</a>
          </li>
          <li class="logout-menu" hidden="hidden">
            <a class="pf-c-dropdown__menu-item" href="#">Log Out</a>
          </li>
        </ul>
      </div>
    </div>
  </header>

  <main class="pf-c-page__main" tabindex="-1">
    <section class="pf-c-page__main-section pf-m-light">
      <div class="pf-c-content">
<h1>ACME Responder</h1>

<h2>Metadata</h2>

<ul>
<li><b>Terms of service:</b> <a id="metadata-termsOfService"></a></li>
<li><b>Website:</b> <a id="metadata-website"></a></li>
<li><b>CAA identities:</b> <span id="metadata-caaIdentities"></span></li>
<li><b>External account required:</b> <span id="metadata-externalAccountRequired"></span></li>
</ul>

<h2>Account Management</h2>

To create an ACME account:

<pre>
$ certbot register \
    --server BASE_URL/directory \
    -m &lt;email address&gt; \
    --agree-tos
</pre>

To update an ACME account:

<pre>
$ certbot update_account \
    --server BASE_URL/directory \
    -m &lt;new email address&gt;
</pre>

To deactivate an ACME account:

<pre>
$ certbot unregister \
    --server BASE_URL/directory
</pre>

<h2>Certificate Enrollment</h2>

To request a certificate with automatic http-01 validation:

<pre>
$ certbot certonly --standalone \
    --server BASE_URL/directory \
    --preferred-challenges http \
    -d server.example.com
</pre>

To request a certificate with manual dns-01 validation:

<pre>
$ certbot certonly --manual \
    --server BASE_URL/directory \
    --preferred-challenges dns \
    -d server.example.com
</pre>

<h2>Certificate Revocation</h2>

To revoke a certificate owned by the ACME account:

<pre>
$ certbot revoke \
    --server BASE_URL/directory \
    --cert-path /etc/letsencrypt/live/server.example.com/fullchain.pem
</pre>

To revoke a certificate associated with a private key:

<pre>
$ certbot revoke \
    --server BASE_URL/directory \
    --cert-path /etc/letsencrypt/live/server.example.com/fullchain.pem \
    --key-path /etc/letsencrypt/live/server.example.com/privkey.pem
</pre>
      </div>
    </section>

  </main>
</div>

</body>
</html>
