<%
  String op = request.getParameter("op");
  if (op == null || op.equals("")) {
    String redirectURL = "/ca/ee/ca";
    response.sendRedirect(redirectURL);
  } else if (op.equals("enroll")) {
    /* redirect to enrollment servlet */
  }
%>
