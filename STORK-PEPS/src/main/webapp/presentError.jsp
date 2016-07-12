<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@taglib prefix="e" uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project" %>

<fmt:setBundle basename="eu.stork.peps.package" var="i18n_eng"/>
<fmt:setBundle basename="errors" var="i18n_error"/>

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
            <div id="margin"><br/>

                <br/>
                <br/>

                <h2><fmt:message key="CPEPS.error.title" bundle="${i18n_eng}"/></h2>
                <hr/>
                <c:if test="${!empty exception}">
                    <p>${exception.errorMessage}
                    </p>
                </c:if>

                <c:if test="${!empty exception.samlTokenFail}">
					<form action="${e:forHtml(errorRedirectUrl)}" name="redirectForm" id="redirectForm" method="post">
						<input type="hidden" name="SAMLResponse" id="SAMLResponse" value="${e:forHtml(exception.samlTokenFail)}" />
						<input type="submit" id="redirectForm_sendButton" name="sendButton" value="send" />
					</form>
                </c:if>
            </div>
        </div>
    </div>
</div>
<script type="text/javascript" src="js/autocompleteOff.js"></script>
</body>
</html>

