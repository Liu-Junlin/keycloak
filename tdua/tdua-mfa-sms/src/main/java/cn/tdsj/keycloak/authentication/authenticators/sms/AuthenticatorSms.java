/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cn.tdsj.keycloak.authentication.authenticators.sms;

import cn.tdsj.dspt.common.util.validate.RegexConst;
import cn.tdsj.dspt.external.ums.common.config.UmsConfig;
import cn.tdsj.dspt.external.ums.common.service.SendService;
import cn.tdsj.dspt.external.ums.schema.proto.UmsInfoProto;
import cn.tdsj.keycloak.authentication.authenticators.sms.jpa.BaseEntity;
import cn.tdsj.keycloak.authentication.authenticators.sms.jpa.TduaSmsMessage;
import cn.tdsj.keycloak.util.ConfigUtil;
import cn.tdsj.keycloak.util.JpaUtil;
import okhttp3.OkHttpClient;
import org.apache.commons.lang3.RandomUtils;
import org.apache.commons.lang3.StringUtils;
import org.jboss.logging.Logger;
import org.jboss.resteasy.specimpl.MultivaluedMapImpl;
import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.events.Details;
import org.keycloak.events.EventType;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;

import javax.persistence.EntityManager;
import javax.persistence.Query;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class AuthenticatorSms implements Authenticator, AuthenticatorFactory {
    public static final String ATTEMPTED_PHONENUMBER = "phoneNumber";
    private static final String USER_PHONE_ATTR = "USER_PHONE_ATTR";

    private static final Logger logger = Logger.getLogger(AuthenticatorSms.class);
    private static final String PROVIDER_ID = "authenticator-sms-tdua";
    private static final String SEND_SMS_CODE = "SEND_SMS_CODE";
    private static final String SMS_SEND_RATE_TEN_MINUTES = "SMS_SEND_RATE_TEN_MINUTES";
    private static final String UMS_SERVER_URL = "UMS_SERVER_URL";
    private static final String UMS_SP_CODE = "UMS_SP_CODE";
    private static final String UMS_LOGIN_NAME = "UMS_LOGIN_NAME";
    private static final String UMS_PASSWORD = "UMS_PASSWORD";
    private static final String UMS_TEMPLATE = "UMS_TEMPLATE";
    private static final int DEFAULT_RATE_TEN_MINUTES = 5;
    private static SendService sendService;
    private static UmsConfig umsConfig;
    private static OkHttpClient DEFAULT_CLIENT;

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel userModel = context.getUser();
        AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
        Map<String, String> config = authenticatorConfig.getConfig();
        String[] userPhoneAttrs = config.get(USER_PHONE_ATTR).split("##");
        String phoneNumber = null;
        for (String userPhoneAttr : userPhoneAttrs) {
            if (StringUtils.isNotBlank(userPhoneAttr)) {
                phoneNumber = userModel.getAttributeStream(userPhoneAttr)
                        .filter(StringUtils::isNotBlank)
                        .findAny()
                        .orElse(null);
                if (StringUtils.isNotBlank(phoneNumber)) {
                    break;
                }
            }
        }
        logger.debugf("Found User PhoneNumber:%s,%s", userModel.getId(), phoneNumber);
        String error = null;
        if (StringUtils.isBlank(phoneNumber)) {
            error = "您的账号未配置正确的手机号";
        } else if (!RegexConst.PHONE_NUMBER_PATTERN.matcher(phoneNumber).matches()) {
            error = "您的账号配置的手机号无效：" + phoneNumber;
        }
        if (error != null) {
            context.getEvent().error(error);
            Response challenge = context.form()
                    .setError(error)
                    .createErrorPage(Response.Status.BAD_REQUEST);
            context.failure(AuthenticationFlowError.INVALID_USER, challenge);
            return;
        }

        AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();
        TduaSmsMessage tduaSmsMessage = new TduaSmsMessage();
        tduaSmsMessage.setPhoneNumber(phoneNumber);
        tduaSmsMessage.setId(KeycloakModelUtils.generateId());
        tduaSmsMessage.setRealmId(context.getRealm().getId());
        tduaSmsMessage.setMessageType(BaseEntity.MessageType.CREDENTIAL_RESET);
        tduaSmsMessage.setSendTime(System.currentTimeMillis());
        int historySend = validHistorySend(context, phoneNumber);
        if (historySend > 0) {
            int rateConfig = ConfigUtil.getConfig(context, SMS_SEND_RATE_TEN_MINUTES, DEFAULT_RATE_TEN_MINUTES);
            if (rateConfig <= 0) {
                rateConfig = DEFAULT_RATE_TEN_MINUTES;
            }
            if (historySend > rateConfig) {
                error = "您的操作过于频繁，请稍候再试。";
                context.getEvent().error(error);
                Response challenge = context.form()
                        .setError(error)
                        .createErrorPage(Response.Status.BAD_REQUEST);
                context.failure(AuthenticationFlowError.INVALID_USER, challenge);
                JpaUtil.getEntityManager(context).persist(tduaSmsMessage);
                return;
            }
        }
        context.setUser(userModel);
        try {
            tduaSmsMessage.setReceiverUserId(userModel.getId());
            String code = sendSms(context, tduaSmsMessage);
            if (code != null) {
                logger.debugf("send sms code:%s", code);
                authenticationSession.setAuthNote(SEND_SMS_CODE, code);
            } else {
                logger.warn("sms code is null");
            }
        } catch (IOException e) {
            tduaSmsMessage.setSuccess(false);
            tduaSmsMessage.setSendResult(e.getMessage());
            logger.error("发送短信异常", e);
        }
        JpaUtil.getEntityManager(context).persist(tduaSmsMessage);
        MultivaluedMap<String, String> formData = new MultivaluedMapImpl<>();
        formData.add(phoneNumber, phoneNumber.substring(0, 3) + "****" + phoneNumber.substring(7));
        Response challenge = context.form().setFormData(formData).createForm("login-phone-captcha.ftl");
        context.challenge(challenge);
    }

    private String sendSms(AuthenticationFlowContext context, TduaSmsMessage tduaSmsMessage) throws IOException {
        AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
        String template = initAndGetTemplate(configModel);
        if (template == null || template.trim().isEmpty()) {
            context.getEvent()
                    .clone()
                    .event(EventType.SEND_RESET_PASSWORD)
                    .detail(Details.USERNAME, tduaSmsMessage.getPhoneNumber())
                    .detail("template", template)
                    .error("UMS配置错误");
        } else {
            UmsInfoProto.UmsInfo.Builder builder = UmsInfoProto.UmsInfo.newBuilder();
            String code = String.valueOf(RandomUtils.nextInt(111111, 999999));
            String content = template.replace("{code}", code);
            builder.setMessageContent(content);
            builder.addUserNumber(tduaSmsMessage.getPhoneNumber());
            tduaSmsMessage.setSendContent(content);
            tduaSmsMessage.setSendTime(System.currentTimeMillis());
            try {
                okhttp3.Response response = sendService.send(builder.build());
                String sendResult = SendService.getSendResult(response);
                logger.debugf("Sms Send Result:%s,%s", tduaSmsMessage.getPhoneNumber(), sendResult);
                if (!sendResult.isEmpty()) {
                    tduaSmsMessage.setSuccess(false);
                    tduaSmsMessage.setSendResult(sendResult);
                } else {
                    tduaSmsMessage.setSuccess(true);
                }
            } catch (IOException e) {
                tduaSmsMessage.setSuccess(false);
                tduaSmsMessage.setSendResult(e.getMessage());
                logger.error("", e);
            }
            return code;
        }
        return null;
    }

    /**
     * 查询十分钟内已发送成功的次数
     *
     * @param context     上下文信息
     * @param phoneNumber 手机号码
     * @return 十分钟内已发送成功的次数
     */
    private int validHistorySend(AuthenticationFlowContext context, String phoneNumber) {
        EntityManager entityManager = JpaUtil.getEntityManager(context);
        String sql = "select count(t) from TduaSmsMessage t where realmId = ?1 and phoneNumber=?2 and sendTime>= ?3";
        Query query = entityManager.createQuery(sql);
        query.setParameter(1, context.getRealm().getId());
        query.setParameter(2, phoneNumber);
        query.setParameter(3, System.currentTimeMillis() - 60 * 10 * 1000);
        return Math.toIntExact((Long) query.getSingleResult());
    }

    private String initAndGetTemplate(AuthenticatorConfigModel configModel) {
        if (configModel != null) {
            Map<String, String> config = configModel.getConfig();
            if (!config.isEmpty()) {
                String umsServerUrl = config.get(UMS_SERVER_URL);
                String umsLoginName = config.get(UMS_LOGIN_NAME);
                String umsPassword = config.get(UMS_PASSWORD);
                String umsSpCode = config.get(UMS_SP_CODE);
                if (umsConfig == null) {
                    umsConfig = new UmsConfig();
                }
                umsConfig.setUmsServerUrl(umsServerUrl);
                umsConfig.setLoginName(umsLoginName);
                umsConfig.setPassword(umsPassword);
                umsConfig.setSpCode(umsSpCode);
                umsConfig.setOkHttpClient(DEFAULT_CLIENT);
                if (sendService == null) {
                    sendService = new SendService(umsConfig);
                } else {
                    sendService.resetUmsConfig(umsConfig);
                }
                return config.get(UMS_TEMPLATE);
            }
        }
        return null;
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (user != null) {
            String phoneCaptcha = formData.getFirst("phoneCaptcha");
            if (phoneCaptcha == null || phoneCaptcha.trim().isEmpty()) {
                Response challenge = context.form()
                        .setError("短信验证码不能为空")
                        .createForm("login-phone-captcha.ftl");
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
            } else {
                String sendSmsCode = context.getAuthenticationSession().getAuthNote(SEND_SMS_CODE);
                if (sendSmsCode != null && !sendSmsCode.trim().isEmpty() && sendSmsCode.trim().equals(phoneCaptcha)) {
                    user.setSingleAttribute("phoneNumberVerified", "true");
                    context.success();
                } else {
                    Response challenge = context.form()
                            .setError("短信验证码不正确")
                            .createForm("login-phone-captcha.ftl");
                    context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
                }
            }
        } else {
            Response challenge = context.form()
                    .setError("手机号无效")
                    .createForm("login-phone-captcha.ftl");
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
        }
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public String getDisplayType() {
        return "Authenticator Sms Tdua";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED
    };

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Authenticator SMS to user and wait for response.";
    }

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>(1);

    static {
        ProviderConfigProperty property = new ProviderConfigProperty();
        property.setName(SMS_SEND_RATE_TEN_MINUTES);
        property.setLabel("十分钟内最多发送次数");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setDefaultValue("5");
        property.setHelpText("十分钟最多发送次数，超过此数值，将被要求稍候再试。默认:" + DEFAULT_RATE_TEN_MINUTES);
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(UMS_SERVER_URL);
        property.setLabel("UMS服务地址");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setDefaultValue("http://sms.api.ums86.com:8899/sms/Api/Send.do");
        property.setHelpText("UMS服务地址");
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(UMS_SP_CODE);
        property.setLabel("UMS客户编码");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setDefaultValue("252851");
        property.setHelpText("UMS SpCode");
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(UMS_LOGIN_NAME);
        property.setLabel("UMS登陆账户名");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setDefaultValue("admin3");
        property.setHelpText("UMS LoginName");
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(UMS_PASSWORD);
        property.setLabel("UMS登陆密码");
        property.setType(ProviderConfigProperty.PASSWORD);
        property.setDefaultValue("p73A6Px7");
        property.setHelpText("UMS Password");
        property.setSecret(true);
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(UMS_TEMPLATE);
        property.setLabel("UMS密码重置模板");
        property.setType(ProviderConfigProperty.TEXT_TYPE);
        property.setDefaultValue("您正在重置双监控系统登陆密码，您本次的验证码为：{code}");
        property.setHelpText("UMS密码重置内容模板，要与短信平台一致，不能随意修改！其中，{code}为短信验证码.");
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(USER_PHONE_ATTR);
        property.setLabel("用户手机号码属性");
        property.setType(ProviderConfigProperty.MULTIVALUED_STRING_TYPE);
        List<String> attrs = new ArrayList<>(5);
        attrs.add(ATTEMPTED_PHONENUMBER);
        property.setDefaultValue(attrs);
        property.setHelpText("用户属性中作为手机号码的字段");
        CONFIG_PROPERTIES.add(property);
    }


    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public void close() {

    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {
        DEFAULT_CLIENT = new OkHttpClient.Builder()
                .connectTimeout(30, TimeUnit.SECONDS)
                .pingInterval(5, TimeUnit.SECONDS)
                .readTimeout(1, TimeUnit.MINUTES)
                .writeTimeout(1, TimeUnit.MINUTES)
                .build();
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
