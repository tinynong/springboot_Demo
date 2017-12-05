package com.xiaour.spring.boot.utils.aes;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Formatter;
import java.util.HashMap;
import java.util.Map;
import java.util.Timer;

import javax.servlet.http.HttpServletRequest;

import com.alibaba.fastjson.JSONObject;
import com.dingtalk.open.client.ServiceFactory;
import com.dingtalk.open.client.api.model.corp.JsapiTicket;
import com.dingtalk.open.client.api.service.corp.CorpConnectionService;
import com.dingtalk.open.client.api.service.corp.JsapiService;
import com.dingtalk.open.client.common.SdkInitException;
import com.dingtalk.open.client.common.ServiceException;
import com.dingtalk.open.client.common.ServiceNotExistException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.xiaour.spring.boot.exception.OApiException;
import com.xiaour.spring.boot.exception.OApiResultException;
import com.xiaour.spring.boot.utils.FileUtils;
import com.xiaour.spring.boot.utils.HttpHelper;
import com.xiaour.spring.boot.utils.JsonUtil;

public class AuthHelper {

	// public static String jsapiTicket = null;
	// public static String accessToken = null;
	public static Timer timer = null;
	// 调整到1小时50分钟
	public static final long cacheTime = 1000 * 60 * 55 * 2;
	public static long currentTime = 0 + cacheTime + 1;
	public static long lastTime = 0;
	public static SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

	/*
	 * 在此方法中，为了避免频繁获取access_token，
	 * 在距离上一次获取access_token时间在两个小时之内的情况，
	 * 将直接从持久化存储中读取access_token
	 * 
	 * 因为access_token和jsapi_ticket的过期时间都是7200秒
	 * 所以在获取access_token的同时也去获取了jsapi_ticket
	 * 注：jsapi_ticket是在前端页面JSAPI做权限验证配置的时候需要使用的
	 * 具体信息请查看开发者文档--权限验证配置
	 */
	public static String getAccessToken() throws OApiException {
		long curTime = System.currentTimeMillis();
		JSONObject accessTokenValue = (JSONObject) FileUtils.getValue("accesstoken", Env.CORP_ID);
		String accToken = "";
		String jsTicket = "";
		JSONObject jsontemp = new JSONObject();
		if (accessTokenValue == null || curTime - accessTokenValue.getLong("begin_time") >= cacheTime) {
			try
			{
			ServiceFactory serviceFactory = ServiceFactory.getInstance();
	        CorpConnectionService corpConnectionService = serviceFactory.getOpenService(CorpConnectionService.class);
	        accToken = corpConnectionService.getCorpToken(Env.CORP_ID, Env.CORP_SECRET);
			// save accessToken
			JSONObject jsonAccess = new JSONObject();
			jsontemp.clear();
			jsontemp.put("access_token", accToken);
			jsontemp.put("begin_time", curTime);
			jsonAccess.put(Env.CORP_ID, jsontemp);
			FileUtils.write2File(jsonAccess, "accesstoken");
			
			if(accToken.length() > 0){
				
				JsapiService jsapiService = serviceFactory.getOpenService(JsapiService.class);

				JsapiTicket JsapiTicket = jsapiService.getJsapiTicket(accToken, "jsapi");
				jsTicket = JsapiTicket.getTicket();
				JSONObject jsonTicket = new JSONObject();
				jsontemp.clear();
				jsontemp.put("ticket", jsTicket);
				jsontemp.put("begin_time", curTime);
				jsonTicket.put(Env.CORP_ID, jsontemp);
				FileUtils.write2File(jsonTicket, "jsticket");
			}
		} catch (SdkInitException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ServiceException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ServiceNotExistException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		} else {
			return accessTokenValue.getString("access_token");
		}

		return accToken;
	}

	// 正常的情况下，jsapi_ticket的有效期为7200秒，所以开发者需要在某个地方设计一个定时器，定期去更新jsapi_ticket
	public static String getJsapiTicket(String accessToken) throws OApiException {
		JSONObject jsTicketValue = (JSONObject) FileUtils.getValue("jsticket", Env.CORP_ID);
		long curTime = System.currentTimeMillis();
		String jsTicket = "";

		 if (jsTicketValue == null || curTime -
		 jsTicketValue.getLong("begin_time") >= cacheTime) {
			ServiceFactory serviceFactory;
			try {
				serviceFactory = ServiceFactory.getInstance();
				JsapiService jsapiService = serviceFactory.getOpenService(JsapiService.class);

				JsapiTicket JsapiTicket = jsapiService.getJsapiTicket(accessToken, "jsapi");
				jsTicket = JsapiTicket.getTicket();

				JSONObject jsonTicket = new JSONObject();
				JSONObject jsontemp = new JSONObject();
				jsontemp.clear();
				jsontemp.put("ticket", jsTicket);
				jsontemp.put("begin_time", curTime);
				jsonTicket.put(Env.CORP_ID, jsontemp);
				FileUtils.write2File(jsonTicket, "jsticket");
			} catch (SdkInitException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (ServiceException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (ServiceNotExistException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			return jsTicket;
		 } else {
			 return jsTicketValue.getString("ticket");
		 }
	}

	public static String sign(String ticket, String nonceStr, long timeStamp, String url) throws OApiException {
		String plain = "jsapi_ticket=" + ticket + "&noncestr=" + nonceStr + "&timestamp=" + String.valueOf(timeStamp)
				+ "&url=" + url;
		try {
			MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
			sha1.reset();
			sha1.update(plain.getBytes("UTF-8"));
			return bytesToHex(sha1.digest());
		} catch (NoSuchAlgorithmException e) {
			throw new OApiResultException(e.getMessage());
		} catch (UnsupportedEncodingException e) {
			throw new OApiResultException(e.getMessage());
		}
	}

	private static String bytesToHex(byte[] hash) {
		Formatter formatter = new Formatter();
		for (byte b : hash) {
			formatter.format("%02x", b);
		}
		String result = formatter.toString();
		formatter.close();
		return result;
	}

	public static String getConfig(HttpServletRequest request) {
		String urlString = request.getRequestURL().toString();
		String queryString = request.getQueryString();
		String agentId=request.getParameter("agentId");

		String queryStringEncode = null;
		String url;
/*		if (queryString != null) {
			try {
				queryStringEncode = URLDecoder.decode(queryString,"UTF-8");
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}
			url = urlString + "?" + queryStringEncode;
		} else {
			url = urlString;
		}*/
		
		String nonceStr = "abcdefg";
		long timeStamp = System.currentTimeMillis() / 1000;
		String signedUrl = urlString;
		String accessToken = null;
		String ticket = null;
		String signature = null;

		try {
			accessToken = AuthHelper.getAccessToken();
	       
			ticket = AuthHelper.getJsapiTicket(accessToken);
			signature = AuthHelper.sign(ticket, nonceStr, timeStamp, signedUrl);
			
		} catch (OApiException  e) {
			e.printStackTrace();
		}
		
		Map<String,Object> data= new HashMap<>();
		
		data.put("jsticket", ticket);
		data.put("signature", signature);
		data.put("nonceStr", nonceStr);
		data.put("timeStamp", timeStamp);
		data.put("corpId", Env.CORP_ID);
		data.put("agentid",agentId);
		
		String configValue = "{jsticket:'" + ticket + "',signature:'" + signature + "',nonceStr:'" + nonceStr + "',timeStamp:'"
		+ timeStamp + "',corpId:'" + Env.CORP_ID + "',agentid:'" + agentId+  "'}";
		
		System.out.println(configValue);
		try {
			return JsonUtil.getJsonString(data);
		} catch (JsonProcessingException e) {
			e.printStackTrace();
		}
		return configValue;
	}


	public static String getSsoToken() throws OApiException {
		String url = "https://oapi.dingtalk.com/sso/gettoken?corpid=" + Env.CORP_ID + "&corpsecret=" + Env.SSO_Secret;
		JSONObject response = HttpHelper.httpGet(url);
		String ssoToken;
		if (response.containsKey("access_token")) {
			ssoToken = response.getString("access_token");
		} else {
			throw new OApiResultException("Sso_token");
		}
		return ssoToken;

	}
	
	
	public static String snsTokenUser(String userCode) throws OApiException {
		String accessToken;
		String url = "https://oapi.dingtalk.com/sns/gettoken?appid="+Env.SNS_APP_ID+"&appsecret="+Env.SNS_APP_SECRET;
		JSONObject response = HttpHelper.httpGet(url);
		
		if (response.containsKey("access_token")) {
			accessToken = response.getString("access_token");
			JSONObject json1=getPersistentCode(accessToken,userCode);
			
			JSONObject json2=getSnsToken(accessToken,json1.getString("openid"),json1.getString("persistent_code"));
			
			String userInfo=getSnsUserinfo(json2.getString("sns_token"));
			return userInfo;
		} else {
			throw new OApiResultException("Sso_token");
		}
	
	}
	
	
	private static JSONObject getPersistentCode(String accessToken,String userCode) throws OApiException{
		String snsUrl = "https://oapi.dingtalk.com/sns/get_persistent_code?access_token="+accessToken;
		
		JSONObject data=new JSONObject();
		data.put("tmp_auth_code", userCode);
		//String jsonStr="{\"tmp_auth_code\": \""+userCode+"\"}";
		JSONObject snsResult = HttpHelper.httpPost(snsUrl, data);
		return snsResult;
	}
	
	private static JSONObject getSnsToken(String accessToken,String openid,String persistentCode) throws OApiException{
		String snsUrl = "https://oapi.dingtalk.com/sns/get_sns_token?access_token="+accessToken;
		JSONObject data=new JSONObject();
			data.put("openid", openid);
			data.put("persistent_code", persistentCode);
			
		//String jsonStr="{\"openid\": \""+openid+"\",\"persistent_code\": \""+persistentCode+"\"}";
		JSONObject snsResult = HttpHelper.httpPost(snsUrl, data);
		return snsResult;
	}
	
	private static String getSnsUserinfo(String snsToken) throws OApiException{
		String snsUrl = "https://oapi.dingtalk.com/sns/getuserinfo?sns_token="+snsToken;
		JSONObject snsResult = HttpHelper.httpGet(snsUrl);
		return snsResult.toJSONString();
	}
	
	
	
	
	public static String getUserinfo(String code) throws OApiException {
		String url = "https://oapi.dingtalk.com/user/getuserinfo?access_token="+getAccessToken()+"&code="+code;
		JSONObject response = HttpHelper.httpGet(url);
		String json= response.toJSONString();
		return json;

	}
	
	

}
