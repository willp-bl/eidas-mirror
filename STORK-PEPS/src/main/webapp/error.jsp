<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<fmt:setBundle basename="eu.stork.peps.package" var="i18n_eng"/>
<%@taglib prefix="e" uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project" %>
<%/* this page is displayed for redirecting error to ServiceProvider*/%>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta http-equiv='pragma' content='no-cache'/>
    <meta http-equiv='cache-control' content='no-cache, no-store, must-revalidate'/>
	<meta http-equiv="Expires" content="-1"/>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
    <title><fmt:message key="stork.title" bundle="${i18n_eng}"/></title>
    <link href="resources/css/stylesheet.css" rel="stylesheet" type="text/css"/>
</head>

<body>
<c:choose>
    <c:when test="${empty errorRedirectUrl}">
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
                        <h2><fmt:message key="missing.parameter.text" bundle="${i18n_eng}"/></h2>
                        <br/>
                    </div>
                </div>
            </div>
        </div>
    </c:when>
    <c:otherwise>
        <form id="redirectForm" name="redirectForm" method="post" action="${e:forHtml(errorRedirectUrl)}">
            <input type="hidden" id="errorCode" name="errorCode" value="${e:forHtml(exception.errorCode)}"/>
            <input type="hidden" id="errorMessage" name="errorMessage" value="${e:forHtml(exception.errorMessage)}"/>
            <input type="hidden" id="SAMLResponse" name="SAMLResponse" value="${e:forHtml(exception.samlTokenFail)}"/>
            <c:if test="RelayState!=null">
                <input type="hidden" id="relayState" name="RelayState" value="${e:forHtml(RelayState)}"/>
            </c:if>

        </form>
    </c:otherwise>
</c:choose>
<jsp:include page="content-security-header-deactivated.jsp"/>
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
                    <form id="redirectFormNoScript" name="redirectFormNoScript" method="post" action="${e:forHtml(errorRedirectUrl)}">
                        <input type="hidden" id="errorCode" name="errorCode" value="${e:forHtml(exception.errorCode)}"/>
                        <input type="hidden" id="errorMessage" name="errorMessage" value="${e:forHtml(exception.errorMessage)}"/>
                        <input type="hidden" id="SAMLResponse" name="SAMLResponse" value="${e:forHtml(exception.samlTokenFail)}"/>
                        <c:if test="RelayState!=null">
                            <input type="hidden" id="relayState" name="RelayState" value="${e:forHtml(RelayState)}"/>
                        </c:if>
                        <input type="submit" id="redirectValue_button" value="<fmt:message key='accept.button' bundle="${i18n_eng}"/>"/>
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
