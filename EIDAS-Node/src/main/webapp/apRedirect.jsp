<!DOCTYPE html>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<fmt:setBundle basename="eu.eidas.node.package" var="i18n_eng"/>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
<%@ taglib prefix="e" uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project" %>
<%@ taglib prefix="token" uri="https://eidas.europa.eu/" %>


<html>

<head>
    <jsp:include page="htmlHead.jsp"/>
    <title><fmt:message key="eidas.title" bundle="${i18n_eng}"/></title>
</head>
<body>
<form id="consentValue" name="redirectForm" method="post" action="${e:forHtml(apUrl)}">
    <input type="hidden" id="consentValue_callbackUrl" name="callbackUrl" value="${e:forHtml(callbackURL)}"/>
    <input type="hidden" id="consentValue_strAttrList" name="strAttrList" value="${e:forHtml(strAttrList)}"/>
    <input type="hidden" id="consentValue_username" name="username" value="${e:forHtml(username)}"/>
</form>
<main>
<noscript>
    <div class="wrapper">
        <jsp:include page="centralSliderNoAnim.jsp"/>
        <jsp:include page="leftColumnNoAnim.jsp"/>
        <div class="col-right">
            <div class="col-right-inner">
                <div class="col-right-content">
                    <jsp:include page="content-security-header-deactivated.jsp"/>
                    <h1 class="title">
                        <span><fmt:message key="eidas.title" bundle="${i18n_eng}"/></span>
                    </h1>
                    <h2 class="sub-title"><fmt:message key="ConnectorRedirect.text" bundle="${i18n_eng}"/></h2>

                        <h2><fmt:message key="APRedirect.text" bundle="${i18n_eng}"/></h2>
                        <br/>
                        <form id="redirectFormNoJs" name="redirectFormNoJs" method="post" action="${e:forHtml(apUrl)}">
                            <input type="hidden" id="consentValue_callbackUrl1" name="callbackUrl" value="${e:forHtml(callbackURL)}"/>
                            <input type="hidden" id="consentValue_strAttrList1" name="strAttrList" value="${e:forHtml(strAttrList)}"/>
                            <input type="hidden" id="consentValue_username1" name="username" value="${e:forHtml(username)}"/>
                            <p class="box-btn">
								<input type="submit" id="ConsentValue_button" class="btn btn-next" value="<fmt:message key='submit.button' bundle="${i18n_eng}"/>"/>
							</P>
                        </form>

                </div>
            </div>
        </div>
    </div>
</noscript>
</main>
<script type="text/javascript" src="js/autocompleteOff.js"></script>
<script type="text/javascript" src="js/redirectOnload.js"></script>
<jsp:include page="footerScripts.jsp"/>
</body>
</html>

