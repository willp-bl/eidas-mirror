<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<fmt:setBundle basename="eu.stork.peps.package" var="i18n_eng"/>
<%@taglib prefix="e" uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project" %>

<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta http-equiv='pragma' content='no-cache'/>
    <meta http-equiv='cache-control' content='no-cache, no-store, must-revalidate'/>
	<meta http-equiv="Expires" content="-1"/>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
    <title>Internal error page</title>
    <link href="resources/css/stylesheet.css" rel="stylesheet" type="text/css"/>
</head>

<body>
<jsp:include page="content-security-header-deactivated.jsp"/>
<form id="ColleagueResponse" name="redirectForm" action="${e:forHtml(redirectUrl)}" method="post">
    <c:if test="${!empty samlTokenFail}" >
        <input type="hidden" name="SAMLResponse" value="${e:forHtml(samlTokenFail)}" id="ColleagueResponse_SAMLResponse"/>
    </c:if>
    <c:if test="${empty samlTokenFail}" >
        <input type="hidden" name="SAMLResponse" value="${e:forHtml(samlToken)}" id="ColleagueResponse_SAMLResponse"/>
    </c:if>
</form>

<noscript>
    <div id="container">

        <div id="header">
            <div class="logo"></div>
            <div class="logo_ue"></div>
            <div class="headerTitle">
                <fmt:message key="stork.title" bundle="${i18n_eng}"/>
            </div>
        </div>
        <div id="border">
            <div id="principal">
                <div id="margin">
                    <h2><fmt:message key="SPEPSRedirect.text" bundle="${i18n_eng}"/></h2>
                    <br/>
                    <form id="ColleagueResponse" name="redirectForm" action="${e:forHtml(redirectUrl)}" method="post">
                        <c:if test="${not empty samlTokenFail}" >a
                            <input type="hidden" name="SAMLResponse" value="${e:forHtml(samlTokenFail)}" id="ColleagueResponse_SAMLResponse"/>
                        </c:if>
                        <c:if test="${empty samlTokenFail}" >b
                            <input type="hidden" name="SAMLResponse" value="${e:forHtml(samlToken)}" id="ColleagueResponse_SAMLResponse"/>
                        </c:if>

                        <fmt:message var="btnMsg" key="accept.button" bundle="${i18n_eng}"/>
                        <input type="submit" id="ColleagueResponse_0" value="${btnMsg}"/>
                        <input type="hidden" name="RelayState" value="${e:forHtml(RelayState)}" id="relayState"/>

                    </form>
                </div>
            </div>
        </div>
    </div>
</noscript>
<script type="text/javascript" src="js/autocompleteOff.js"></script>
<script type="text/javascript" src="js/redirectOnload.js"></script>
</body>
</html>
