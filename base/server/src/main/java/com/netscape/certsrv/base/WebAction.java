package com.netscape.certsrv.base;

import static java.lang.annotation.ElementType.METHOD;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.dogtagpki.server.rest.v2.PKIServlet;

@Target(METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface WebAction {

    PKIServlet.HttpMethod method();

    String[] paths();

}
