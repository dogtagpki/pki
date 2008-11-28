<!-- --- BEGIN COPYRIGHT BLOCK ---
     Copyright (C) 2006 Red Hat, Inc.
     All rights reserved.
     --- END COPYRIGHT BLOCK --- -->
<%
  String op = request.getParameter("op");
  if (op == null || op.equals("")) {
    String redirectURL = "/ca/ee/ca";
    response.sendRedirect(redirectURL);
  } else if (op.equals("enroll")) {
    /* redirect to enrollment servlet */
  }
%>
