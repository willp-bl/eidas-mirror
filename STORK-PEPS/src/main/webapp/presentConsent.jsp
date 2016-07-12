<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<fmt:setBundle basename="eu.stork.peps.package" var="i18n_eng"/>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
<%@ taglib prefix="e" uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project" %>
<%@ taglib prefix="token" uri="https://www.eid-stork.eu/" %>

<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta http-equiv='pragma' content='no-cache'/>
    <meta http-equiv='cache-control' content='no-cache, no-store, must-revalidate'/>
	<meta http-equiv="Expires" content="-1"/>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
    <title><fmt:message key="consent.page.title" bundle="${i18n_eng}"/></title>
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
            <div id="margin">

                <h2>
				<c:if test="${eidasAttributes}">
                    <fmt:message key="CitizenConsentActionEidas.text" bundle="${i18n_eng}">
                        <fmt:param value="${e:forHtml(spId)}"/>
                        <fmt:param value="${e:forHtml(LoA)}"/>
                    </fmt:message>
				</c:if>
				<c:if test="${!eidasAttributes}">
                    <fmt:message key="CitizenConsentAction.text" bundle="${i18n_eng}">
                        <fmt:param value="${e:forHtml(spId)}"/>
                        <fmt:param value="${e:forHtml(qaaLevel)}"/>
                    </fmt:message>
				</c:if>
                </h2>
                <br/>
                <span id="formContainer">
                    <form id="consentSelector" name="consentSelector" method="post" action="${e:forHtml(citizenConsentUrl)}">
                        <token:token/>
                        <table cellpadding="1" cellspacing="1">
                            <tr>
                                <td>
                                    <h4><fmt:message key="attribute.mandatory" bundle="${i18n_eng}"/></h4>
                                </td>
                            </tr>
							<c:if test="${eidasAttributes}">
								<c:set var="categoryIsDisplayed" value="false"/>
								<c:forEach items="${attrList}" var="attrItem">
									<c:if test="${attrItem.required && attrItem.eidasNaturalPersonAttr}">
										<c:if test="${categoryIsDisplayed=='false'}">
											<tr>
												<td align="right" valign="top"></td>
												<td align="left" valign="top"><h4><fmt:message key="attribute.naturalperson" bundle="${i18n_eng}"/></h4>
												</td>
											</tr>
											<c:set var="categoryIsDisplayed" value="true"/>
										</c:if>
										<tr>
											<td align="right" valign="top"></td>
											<td align="left" valign="top"><fmt:message var="displayAttr" key="${attrItem.name}.display" bundle="${i18n_eng}"/>
												<c:if test="${!fn:startsWith(fn:toLowerCase(displayAttr), 'false')}">
													<input id="consentSelector_${attrItem.name}" type="checkbox" name="${attrItem.name}" checked="checked" disabled="disabled" value="true"/>
													<label class="checkboxLabel" for="consentSelector_${attrItem.name}"><fmt:message key="${attrItem.name}" bundle="${i18n_eng}"/></label>
												</c:if>
												<input id="consentSelector_${attrItem.name}" type="hidden" name="${attrItem.name}" value="${attrItem.name}"/>
											</td>
										</tr>
									</c:if>
								</c:forEach>
								<c:set var="categoryIsDisplayed" value="false"/>
								<c:forEach items="${attrList}" var="attrItem">
									<c:if test="${attrItem.required && attrItem.eidasLegalPersonAttr}">
										<c:if test="${categoryIsDisplayed=='false'}">
											<tr>
												<td align="right" valign="top"></td>
												<td align="left" valign="top"><h4><fmt:message key="attribute.legalperson" bundle="${i18n_eng}"/></h4>
												</td>
											</tr>
											<c:set var="categoryIsDisplayed" value="true"/>
										</c:if>
										<tr>
											<td align="right" valign="top"></td>
											<td align="left" valign="top"><fmt:message var="displayAttr" key="${attrItem.name}.display" bundle="${i18n_eng}"/>
												<c:if test="${!fn:startsWith(fn:toLowerCase(displayAttr), 'false')}">
													<input id="consentSelector_${attrItem.name}" type="checkbox" name="${attrItem.name}" checked="checked" disabled="disabled" value="true"/>
													<label class="checkboxLabel" for="consentSelector_${attrItem.name}"><fmt:message key="${attrItem.name}" bundle="${i18n_eng}"/></label>
												</c:if>
												<input id="consentSelector_${attrItem.name}" type="hidden" name="${attrItem.name}" value="${attrItem.name}"/>
											</td>
										</tr>
									</c:if>
								</c:forEach>
							</c:if>
							<c:if test="${!eidasAttributes}">
								<c:forEach items="${attrList}" var="attrItem">
									<c:if test="${attrItem.required}">
										<tr>
											<td align="right" valign="top"></td>
											<td align="left" valign="top"><fmt:message var="displayAttr" key="${attrItem.name}.display" bundle="${i18n_eng}"/>
												<c:if test="${!fn:startsWith(fn:toLowerCase(displayAttr), 'false')}">
													<input id="consentSelector_${attrItem.name}" type="checkbox" name="${attrItem.name}" checked="checked" disabled="disabled" value="true"/>
													<label class="checkboxLabel" for="consentSelector_${attrItem.name}"><fmt:message key="${attrItem.name}" bundle="${i18n_eng}"/></label>
												</c:if>
												<input id="consentSelector_${attrItem.name}" type="hidden" name="${attrItem.name}" value="${attrItem.name}"/>
											</td>
										</tr>
									</c:if>
								</c:forEach>
							</c:if>
                            <tr>
                                <td>
                                    <h4><fmt:message key="attribute.optional" bundle="${i18n_eng}"/></h4>
                                </td>
                            </tr>
							<c:if test="${eidasAttributes}">
								<c:set var="categoryIsDisplayed" value="false"/>
								<c:forEach items="${attrList}" var="attrItem">
									<c:if test="${!attrItem.required && attrItem.eidasNaturalPersonAttr}">
										<c:if test="${categoryIsDisplayed=='false'}">
												<tr>
													<td align="right" valign="top"></td>
													<td align="left" valign="top"><h4><fmt:message key="attribute.naturalperson" bundle="${i18n_eng}"/></h4>
													</td>
												</tr>
											<c:set var="categoryIsDisplayed" value="true"/>
										</c:if>
										<tr>
											<td align="right" valign="top"></td>
											<td align="left" valign="top"><fmt:message var="displayAttr" key="${attrItem.name}.display" bundle="${i18n_eng}"/>
												<c:if test="${fn:startsWith(fn:toLowerCase(displayAttr), 'false')}">
													<input id="consentSelector_${attrItem.name}" type="hidden" name="${attrItem.name}" value="${attrItem.name}"/>
												</c:if>
												<c:if test="${!fn:startsWith(fn:toLowerCase(displayAttr), 'false')}">
													<input id="consentSelector_${attrItem.name}" type="checkbox" name="${attrItem.name}" value="true"/>
													<label class="checkboxLabel" for="consentSelector_${attrItem.name}"><fmt:message key="${attrItem.name}" bundle="${i18n_eng}"/></label>
													<input id="__checkbox_consentSelector_${attrItem.name}" type="hidden" name="__checkbox_${attrItem.name}" value="true"/>
												</c:if>
											</td>
										</tr>
									</c:if>
								</c:forEach>
								<c:set var="categoryIsDisplayed" value="false"/>
								<c:forEach items="${attrList}" var="attrItem">
									<c:if test="${!attrItem.required && attrItem.eidasLegalPersonAttr}">
										<c:if test="${categoryIsDisplayed=='false'}">
												<tr>
													<td align="right" valign="top"></td>
													<td align="left" valign="top"><h4><fmt:message key="attribute.legalperson" bundle="${i18n_eng}"/></h4>
													</td>
												</tr>
											<c:set var="categoryIsDisplayed" value="true"/>
										</c:if>
										<tr>
											<td align="right" valign="top"></td>
											<td align="left" valign="top"><fmt:message var="displayAttr" key="${attrItem.name}.display" bundle="${i18n_eng}"/>
												<c:if test="${fn:startsWith(fn:toLowerCase(displayAttr), 'false')}">
													<input id="consentSelector_${attrItem.name}" type="hidden" name="${attrItem.name}" value="${attrItem.name}"/>
												</c:if>
												<c:if test="${!fn:startsWith(fn:toLowerCase(displayAttr), 'false')}">
													<input id="consentSelector_${attrItem.name}" type="checkbox" name="${attrItem.name}" value="true"/>
													<label class="checkboxLabel" for="consentSelector_${attrItem.name}"><fmt:message key="${attrItem.name}" bundle="${i18n_eng}"/></label>
													<input id="__checkbox_consentSelector_${attrItem.name}" type="hidden" name="__checkbox_${attrItem.name}" value="true"/>
												</c:if>
											</td>
										</tr>
									</c:if>
								</c:forEach>
							</c:if>
							<c:if test="${!eidasAttributes}">
								<c:forEach items="${attrList}" var="attrItem">
									<c:if test="${!attrItem.required}">
										<tr><td align="right" valign="top"></td>
											<td align="left" valign="top"><fmt:message var="displayAttr" key="${attrItem.name}.display" bundle="${i18n_eng}"/>
												<c:if test="${fn:startsWith(fn:toLowerCase(displayAttr), 'false')}">
													<input id="consentSelector_${attrItem.name}" type="hidden" name="${attrItem.name}" value="${attrItem.name}"/>
												</c:if>
												<c:if test="${!fn:startsWith(fn:toLowerCase(displayAttr), 'false')}">
													<input id="consentSelector_${attrItem.name}" type="checkbox" name="${attrItem.name}" value="true"/>
													<label class="checkboxLabel" for="consentSelector_${attrItem.name}"><fmt:message key="${attrItem.name}" bundle="${i18n_eng}"/></label>
													<input id="__checkbox_consentSelector_${attrItem.name}" type="hidden" name="__checkbox_${attrItem.name}" value="true"/>
												</c:if>
											</td>
										</tr>
									</c:if>
								</c:forEach>
							</c:if>
                        </table>
                        <%--<div><s:submit value="send"/></div>--%>
                    </form>
                    <form id="cancelForm" name="cancelForm" method="post" action="${e:forHtml(redirectUrl)}">
                        <input type="hidden" id="SAMLResponse" name="SAMLResponse" value="<c:out value='${e:forHtml(samlTokenFail)}'/>"/>
                        <token:token/>
                        <%-- <div class="cancelButton"><s:submit value="cancel"/></div>--%>
                    </form>
                </span><br/><br/>
                <div id="buttonBar" class="cancelButton">
                    <button type="button" id="buttonBar.send"><fmt:message key="button.send" bundle="${i18n_eng}" /> </button>
                    <button type="button" id="buttonBar.cancel"><fmt:message key="button.cancel" bundle="${i18n_eng}" /></button>
                </div>
            </div>
        </div>
    </div>
</div>
<script type="text/javascript" src="js/autocompleteOff.js"></script>
<script type="text/javascript" src="js/redirectConsent.js"></script>
</body>
</html>
