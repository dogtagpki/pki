<!--
Copyright Red Hat, Inc.

SPDX-License-Identifier: GPL-2.0-or-later
-->
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
$ certbot certonly \
    --server BASE_URL/directory \
    --standalone \
    --preferred-challenges http \
    -d server.example.com
</pre>

To request a certificate with manual dns-01 validation:

<pre>
$ certbot certonly \
    --server BASE_URL/directory \
    --manual \
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

<h2>See Also</h2>

<ul>
<li><a href="https://certbot.eff.org">certbot</a></li>
</ul>
