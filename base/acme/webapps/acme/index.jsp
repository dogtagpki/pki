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
    updateBaseURL();
    updateLoginInfo();

    activateProfileMenu();
    activateSidebarMenu();
    activateSidebarToggle();

    loadPage("home.jsp", function() {
        updateHomePage();
    });
});
    </script>
</head>
<body>

<div class="pf-c-page">

  <header class="pf-c-page__header">
    <div class="pf-c-page__header-brand">
      <div class="pf-c-page__header-brand-toggle">
        <button id="sidebar-toggle" class="pf-c-button pf-m-plain" type="button" aria-label="Global navigation" aria-controls="sidebar">
          <i class="fas fa-bars" aria-hidden="true"></i>
        </button>
      </div>
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

  <div class="pf-c-page__sidebar">
    <div class="pf-c-page__sidebar-body">
      <nav id="sidebar" class="pf-c-nav" aria-label="Global">
        <ul class="pf-c-nav__list">
          <li class="home-menu pf-c-nav__item">
            <a href="#" class="pf-c-nav__link pf-m-current" aria-current="page">Home</a>
          </li>
          <li class="services-menu pf-c-nav__item">
            <a href="#" class="pf-c-nav__link">Services</a>
          </li>
          <li class="config-menu pf-c-nav__item" hidden="hidden">
            <a href="#" class="pf-c-nav__link">Configuration</a>
          </li>
          <li class="login-menu pf-c-nav__item" hidden="hidden">
            <a href="#" class="pf-c-nav__link">Log In</a>
          </li>
          <li class="logout-menu pf-c-nav__item" hidden="hidden">
            <a href="#" class="pf-c-nav__link">Log Out</a>
          </li>
        </ul>
      </nav>
    </div>
  </div>

  <main class="pf-c-page__main" tabindex="-1">
    <section class="pf-c-page__main-section pf-m-light">
      <div class="pf-c-content">
      </div>
    </section>

  </main>
</div>

</body>
</html>
