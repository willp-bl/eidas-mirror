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

    <c:if test="${!empty exception.samlTokenFail}">
        <form action="${e:forHtml(errorRedirectUrl)}" name="redirectForm" id="redirectForm" method="post">
            <input type="hidden" name="SAMLResponse" id="SAMLResponse" value="${e:forHtml(exception.samlTokenFail)}" />
        </form>
    </c:if>
</div>
<script type="text/javascript" src="js/autocompleteOff.js"></script>
<script type="text/javascript" src="js/redirectOnload.js"></script>
</body>
</html>

