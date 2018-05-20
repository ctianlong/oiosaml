/*
 * The contents of this file are subject to the Mozilla Public 
 * License Version 1.1 (the "License"); you may not use this 
 * file except in compliance with the License. You may obtain 
 * a copy of the License at http://www.mozilla.org/MPL/
 * 
 * Software distributed under the License is distributed on an 
 * "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, either express 
 * or implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 *
 * The Original Code is OIOSAML Java Service Provider.
 * 
 * The Initial Developer of the Original Code is Trifork A/S. Portions 
 * created by Trifork A/S are Copyright (C) 2008 Danish National IT 
 * and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 * 
 * Contributor(s):
 *   Joakim Recht <jre@trifork.com>
 *   Rolf Njor Jensen <rolf@trifork.com>
 *
 */
package dk.itst.oiosaml.sp.service;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collection;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;

import org.apache.commons.configuration.Configuration;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.opensaml.saml2.core.Assertion;

import dk.itst.oiosaml.common.DBException;
import dk.itst.oiosaml.common.JDBCUtils;
import dk.itst.oiosaml.common.MD5FileUtil;
import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.logging.Audit;
import dk.itst.oiosaml.logging.Operation;
import dk.itst.oiosaml.sp.AuthenticationHandler;
import dk.itst.oiosaml.sp.PassiveUserAssertion;
import dk.itst.oiosaml.sp.UserAssertion;
import dk.itst.oiosaml.sp.UserAssertionImpl;
import dk.itst.oiosaml.sp.UserAttribute;
import dk.itst.oiosaml.sp.metadata.IdpMetadata.Metadata;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.model.OIOResponse;
import dk.itst.oiosaml.sp.model.RelayState;
import dk.itst.oiosaml.sp.model.validation.AssertionValidator;
import dk.itst.oiosaml.sp.service.util.ArtifactExtractor;
import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.sp.service.util.HttpSOAPClient;
import dk.itst.oiosaml.sp.service.util.PostResponseExtractor;
import dk.itst.oiosaml.sp.service.util.SOAPClient;
import dk.itst.oiosaml.sp.service.util.Utils;

/**
 * Servlet for receiving SAML asertions from the IdP.
 * 
 * <p>The servlet supports both POST and Artifact binding. POST reception is handled by
 * {@link PostResponseExtractor} while Artifact is handled by {@link ArtifactExtractor}.</p>
 * 
 * <p>Upon reception, SAML responses are validated using {@link OIOResponse#validateResponse(String, java.security.cert.Certificate)},
 * and the attached signature is also checked.</p>
 * 
 *  <p>If the SAML response can be validated, and is a known response, the received assertion
 *  is set in the user's session using {@link LoggedInHandler#setAssertion(HttpSession, OIOAssertion)}. The
 *  user is then redirected either to the home url, or to the url saved in the session attributes
 *  {@link Constants#SESSION_REQUESTURI} and {@link Constants#SESSION_QUERYSTRING}.
 * 
 * @author Joakim Recht <jre@trifork.com>
 * @author Rolf Njor Jensen <rolf@trifork.com>
 */
public class SAMLAssertionConsumerHandler implements SAMLHandler {

	@SuppressWarnings("unused")
	private static final long serialVersionUID = -8417816228519917989L;
	public static final String VERSION = "$Id: SAMLAssertionConsumerHandler.java 2910 2008-05-21 13:07:31Z jre $";
	
	private static final Logger log = Logger.getLogger(SAMLAssertionConsumerHandler.class);
	private SOAPClient client;
	private final AssertionValidator validator;

	public SAMLAssertionConsumerHandler(Configuration config) {
		this.validator = (AssertionValidator) Utils.newInstance(config, Constants.PROP_VALIDATOR);
		setSoapClient(new HttpSOAPClient());
	}
	
	public void setSoapClient(SOAPClient soapClient) {
		client = soapClient;
	}

	public void handlePost(RequestContext ctx) throws IOException, ServletException {
		PostResponseExtractor extractor = new PostResponseExtractor();
		handleSAMLResponse(ctx, extractor.extract(ctx.getRequest()));
	}


	/**
	 * Receive an artifact from the login site and make a back channel call &lt;ArtifactResolve&gt;
	 * to the login site in order to obtain the associated {@link OIOAssertion}
	 */
	public void handleGet(RequestContext ctx) throws IOException, ServletException {
		if (ctx.getRequest().getParameter(Constants.SAML_SAMLRESPONSE) != null) {
			handlePost(ctx);
		} else {
			ArtifactExtractor extractor = new ArtifactExtractor(ctx.getIdpMetadata(), ctx.getSpMetadata().getEntityID(), 
					client, ctx.getConfiguration().getString(Constants.PROP_RESOLVE_USERNAME), 
					ctx.getConfiguration().getString(Constants.PROP_RESOLVE_PASSWORD),
					ctx.getConfiguration().getBoolean(Constants.PROP_IGNORE_CERTPATH, false));
			handleSAMLResponse(ctx, extractor.extract(ctx.getRequest()));
		}
	} 
	
	private void handleSAMLResponse(RequestContext ctx, OIOResponse response) throws IOException, ServletException {
		Audit.log(Operation.AUTHNREQUEST_SEND, false, response.getInResponseTo(), response.toXML());
		
		HttpSession session = ctx.getSession();
		
		if (log.isDebugEnabled()) {
			log.debug("Calling URL.:" + ctx.getRequest().getRequestURI() + "?" + ctx.getRequest().getQueryString());
			log.debug("SessionId..:" + session.getId());
		}

		RelayState relayState = RelayState.fromRequest(ctx.getRequest());
		if (log.isDebugEnabled()) log.debug("Got relayState..:" + relayState);

		String idpEntityId = response.getOriginatingIdpEntityId(ctx.getSessionHandler());
		if (log.isDebugEnabled()) log.debug("Received SAML Response from " + idpEntityId + ": " + response.toXML());
		
		boolean allowPassive = ctx.getConfiguration().getBoolean(Constants.PROP_PASSIVE, false);
		Metadata metadata = ctx.getIdpMetadata().getMetadata(idpEntityId);
		response.decryptAssertion(ctx.getCredential(), !ctx.getConfiguration().getBoolean(Constants.PROP_REQUIRE_ENCRYPTION, false));
		response.validateResponse(ctx.getSpMetadata().getAssertionConsumerServiceLocation(0), metadata.getValidCertificates(), allowPassive);
		if (allowPassive && response.isPassive()) {
			log.debug("Received passive response, setting passive userassertion");
			Assertion assertion = SAMLUtil.buildXMLObject(Assertion.class);
			assertion.setID("" + System.currentTimeMillis());
			ctx.getSessionHandler().setAssertion(session.getId(), new OIOAssertion(assertion));
			PassiveUserAssertion passiveUserAssertion = new PassiveUserAssertion(ctx.getConfiguration().getString(Constants.PROP_PASSIVE_USER_ID));
			session.setAttribute(Constants.SESSION_USER_ASSERTION, passiveUserAssertion);
			
			Audit.log(Operation.LOGIN, passiveUserAssertion.getSubject());
			// 标记，以备出错排查
			System.out.println("--- is passive ---");
		} else {
			OIOAssertion assertion = response.getAssertion();
	
			assertion.validateAssertion(validator, ctx.getSpMetadata().getEntityID(), ctx.getSpMetadata().getAssertionConsumerServiceLocation(0));

			UserAssertion userAssertion = new UserAssertionImpl(assertion);
			if (!invokeAuthenticationHandler(ctx, userAssertion)) {
				Audit.logError(Operation.LOGIN, false, response.getInResponseTo(), "Authentication handler stopped authentication");
				log.error("Authentication handler stopped authentication");
				return;
			}
			Audit.setAssertionId(assertion.getID());
			Audit.log(Operation.LOGIN, assertion.getSubjectNameIDValue() + "/" + assertion.getAssuranceLevel() + " via " + assertion.getIssuer());
			Audit.log(Operation.LOGIN_SESSION, Integer.toString(session.getMaxInactiveInterval()));
			
			// Store the assertion in the session store
			
			// release the DOM tree now the signature is validated - due to large memory consumption
			Assertion assertion2 = assertion.getAssertion();
			assertion2.releaseChildrenDOM(true);
            assertion2.releaseDOM();
            assertion2.detach();
			
			ctx.getSessionHandler().setAssertion(session.getId(), assertion);
			session.setAttribute(Constants.SESSION_USER_ASSERTION, userAssertion);
			
			// 发送用户信息到业务系统
			redirectToSP(userAssertion, ctx);
		}
		// 取消原来的跳转逻辑
//		if (relayState.getRelayState() != null) {
//			HTTPUtils.sendResponse(ctx.getSessionHandler().getRequest(relayState.getRelayState()), ctx);
//		} else {
//			HTTPUtils.sendResponse(null, ctx);
//		}
	}

    private boolean invokeAuthenticationHandler(RequestContext ctx, UserAssertion userAssertion) {
		String handlerClass = ctx.getConfiguration().getString(Constants.PROP_AUTHENTICATION_HANDLER, null);
		if (handlerClass != null) {
			log.debug("Authentication handler: " + handlerClass);
			
			AuthenticationHandler handler = (AuthenticationHandler) Utils.newInstance(ctx.getConfiguration(), Constants.PROP_AUTHENTICATION_HANDLER);
			return handler.userAuthenticated(userAssertion, ctx.getRequest(), ctx.getResponse());
		} else {
			log.debug("No authentication handler configured");
			return true;
		}
	}
    
    private void redirectToSP(UserAssertion userAssertion, RequestContext ctx) throws IOException {
		//System.out.println("login: put sessionId " + session.getId() + " into sessionMap");
		// 将从IDP接受到的登录用户信息加密传输给业务系统 v1.0
    	Configuration conf = ctx.getConfiguration();
    	String uid = userAssertion.getAttribute("uid").getValue(); // 获取学工号
    	String key = conf.getString(Constants.PROP_LOGIN_TOKEN_KEY); // 获取传输加密key
		long vaildtime = conf.getLong(Constants.PROP_LOGIN_TOKEN_VAILDTIME, 60000); // 获取token最长有效时间
		long time = System.currentTimeMillis() / vaildtime; // 时间戳处理
		String token = MD5FileUtil.getMD5String(uid + key + time);
		StringBuilder url = new StringBuilder(conf.getString(Constants.PROP_LOGIN_RESPONSE));
		url.append("?token=");
		url.append(token);
		url.append("&uid=");
		url.append(uid);
		int pid = conf.getInt("oiosaml-sp.login.info.table.num", 0);
		switch (pid) {
		case 1:
			concatPidOrPhoneOnUrlByUidFromOneDB(url, uid, ctx);
			break;
		case 2:
			concatPidOrPhoneOnUrlByUidFromTwoDB(url, uid, ctx);
			break;
		default:
			break;
		}
		Collection<UserAttribute> attributes = userAssertion.getAllAttributes();
		for (UserAttribute a : attributes) {
			String name = a.getName();
			if("uid".equals(name) || "dk:gov:saml:attribute:SpecVer".equals(name)) continue;
			url.append("&");
			url.append(URLEncoder.encode(name, "UTF-8"));
			url.append("=");
			url.append(URLEncoder.encode(a.getValue(), "UTF-8"));
		}
		ctx.getResponse().sendRedirect(url.toString());
    }
    
    private void concatPidOrPhoneOnUrlByUidFromOneDB(StringBuilder url, String uid, RequestContext ctx) throws UnsupportedEncodingException {
    	Configuration conf = ctx.getConfiguration();
    	boolean isNeedPid = conf.getBoolean("oiosaml-sp.login.pid.enable", false);
    	boolean isNeedPhone = conf.getBoolean("oiosaml-sp.login.phone.enable", false);
    	if (!isNeedPid && !isNeedPhone)
    		return;
    	StringBuilder sql = new StringBuilder("SELECT ");
    	if (isNeedPid) {
    		sql.append(conf.getString("oiosaml-sp.login.pid.column"));
    		if (isNeedPhone) {
    			sql.append(", ");
    			sql.append(conf.getString("oiosaml-sp.login.phone.column"));
    		}
    	} else {
    		sql.append(conf.getString("oiosaml-sp.login.phone.column"));
    	}
    	sql.append(" FROM ");
    	sql.append(conf.getString("oiosaml-sp.login.table.all"));
    	sql.append(" WHERE ");
    	sql.append(conf.getString("oiosaml-sp.login.uid.column"));
    	sql.append(" = ?");
    	Connection conn = null;
		PreparedStatement pStatement = null;
		ResultSet resultSet = null;
		try {
			conn = JDBCUtils.getConnectionAll();
			pStatement = conn.prepareStatement(sql.toString());
			pStatement.setObject(1, uid);
			resultSet = pStatement.executeQuery();
			if(resultSet.next()){
				if (isNeedPid) {
					String pid = resultSet.getString(1);
					if (StringUtils.isNotBlank(pid)) {
						url.append("&pid=");
						url.append(URLEncoder.encode(pid, "UTF-8"));
					}
					String phone = resultSet.getString(2);
					if (isNeedPhone && StringUtils.isNotBlank(phone)) {
						url.append("&phone=");
						url.append(URLEncoder.encode(phone, "UTF-8"));
					}
				} else {
					String phone = resultSet.getString(1);
					if (StringUtils.isNotBlank(phone)) {
						url.append("&phone=");
						url.append(URLEncoder.encode(phone, "UTF-8"));
					}
				}
			}
		} catch (SQLException e) {
			e.printStackTrace();
			throw new DBException("获取数据库用户信息失败");
		} finally {
			JDBCUtils.release(conn, pStatement, resultSet);
		}
    }
    
    private void concatPidOrPhoneOnUrlByUidFromTwoDB(StringBuilder url, String uid, RequestContext ctx) throws UnsupportedEncodingException {
    	Configuration conf = ctx.getConfiguration();
    	boolean isNeedPid = conf.getBoolean("oiosaml-sp.login.pid.enable", false);
    	boolean isNeedPhone = conf.getBoolean("oiosaml-sp.login.phone.enable", false);
    	if (!isNeedPid && !isNeedPhone)
    		return;
    	Connection conn = null;
    	PreparedStatement pStatement = null;
    	ResultSet resultSet = null;
    	if (isNeedPhone) {
    		StringBuilder sql = new StringBuilder("SELECT ");
    		sql.append(conf.getString("oiosaml-sp.login.pid.column"));
    		sql.append(" FROM ");
    		sql.append(conf.getString("oiosaml-sp.login.table.first"));
    		sql.append(" WHERE ");
    		sql.append(conf.getString("oiosaml-sp.login.uid.column"));
        	sql.append(" = ?");
        	String pid = null;
        	try {
        		conn = JDBCUtils.getConnectionFirst();
        		pStatement = conn.prepareStatement(sql.toString());
				pStatement.setObject(1, uid);
				resultSet = pStatement.executeQuery();
				if (resultSet.next()) {
					pid = resultSet.getString(1);
					if (isNeedPid && StringUtils.isNotBlank(pid)) {
						url.append("&pid=");
						url.append(URLEncoder.encode(pid, "UTF-8"));
					}
				}
			} catch (SQLException e) {
	    		e.printStackTrace();
	    		throw new DBException("获取数据库用户信息失败");
	    	} finally {
	    		JDBCUtils.release(conn, pStatement, resultSet);
	    	}
        	if (StringUtils.isNotBlank(pid)) {
        		sql.setLength(0);
        		sql.append("SELECT ");
        		sql.append(conf.getString("oiosaml-sp.login.phone.column"));
        		sql.append(" FROM ");
        		sql.append(conf.getString("oiosaml-sp.login.table.second"));
        		sql.append(" WHERE ");
        		sql.append(conf.getString("oiosaml-sp.login.pid.column2"));
        		sql.append(" = ?");
        		try {
        			conn = JDBCUtils.getConnectionSecond();
        			pStatement = conn.prepareStatement(sql.toString());
        			pStatement.setObject(1, pid);
        			resultSet = pStatement.executeQuery();
        			if (resultSet.next()) {
        				String phone = resultSet.getString(1);
    					if (StringUtils.isNotBlank(phone)) {
    						url.append("&phone=");
    						url.append(URLEncoder.encode(phone, "UTF-8"));
    					}
        			}
        		} catch (SQLException e) {
        			e.printStackTrace();
        			throw new DBException("获取数据库用户信息失败");
        		} finally {
        			JDBCUtils.release(conn, pStatement, resultSet);
        		}
        	}
    	} else {
    		StringBuilder sql = new StringBuilder("SELECT ");
    		sql.append(conf.getString("oiosaml-sp.login.pid.column"));
    		sql.append(" FROM ");
    		sql.append(conf.getString("oiosaml-sp.login.table.first"));
    		sql.append(" WHERE ");
    		sql.append(conf.getString("oiosaml-sp.login.uid.column"));
        	sql.append(" = ?");
        	try {
        		conn = JDBCUtils.getConnectionFirst();
        		pStatement = conn.prepareStatement(sql.toString());
				pStatement.setObject(1, uid);
				resultSet = pStatement.executeQuery();
				if (resultSet.next()) {
					String pid = resultSet.getString(1);
					if (isNeedPid && StringUtils.isNotBlank(pid)) {
						url.append("&pid=");
						url.append(URLEncoder.encode(pid, "UTF-8"));
					}
				}
        	} catch (SQLException e) {
        		e.printStackTrace();
	    		throw new DBException("获取数据库用户信息失败");
			} finally {
				JDBCUtils.release(conn, pStatement, resultSet);
			}
    	}
    }

}
