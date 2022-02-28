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

package cn.tdsj.keycloak.authentication.authenticators.resetcred;

import cn.tdsj.dspt.common.util.validate.RegexConst;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.provider.ProviderConfigProperty;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class ResetCredentialChooseUser extends org.keycloak.authentication.authenticators.resetcred.ResetCredentialChooseUser {
    private static final Logger logger = Logger.getLogger(ResetCredentialChooseUser.class);
    public static final String PROVIDER_ID = "reset-credentials-choose-user-tdua";
    public static final String ATTEMPTED_PHONENUMBER = "userName";
    private static final String USER_PHONE_ATTR = "USER_PHONE_ATTR";

    @Override
    public void action(AuthenticationFlowContext context) {
        EventBuilder event = context.getEvent();
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String phoneNumber = formData.getFirst(ATTEMPTED_PHONENUMBER);
        if (phoneNumber == null || !RegexConst.PHONE_NUMBER_PATTERN.matcher(phoneNumber).matches()) {
            event.error("手机号无效");
            Response challenge = context.form()
                    .setError("手机号码格式不正确")
                    .createPasswordReset();
            context.failureChallenge(AuthenticationFlowError.UNKNOWN_USER, challenge);
            return;
        }
        RealmModel realm = context.getRealm();
        UserProvider userProvider = context.getSession().users();
        UserModel userModel = userProvider.getUserByUsername(realm, phoneNumber);
        if (userModel == null) {
            AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
            Map<String, String> config = authenticatorConfig.getConfig();
            String[] userPhoneAttrs = config.get(USER_PHONE_ATTR).split("##");
            for (String attr : userPhoneAttrs) {
                logger.debugf("Phone Attr:%s", attr);
                if (attr != null) {
                    List<UserModel> userModelList = userProvider.searchForUserByUserAttributeStream(realm, attr, phoneNumber)
                            .filter(u -> {
                                Map<String, List<String>> attributes = u.getAttributes();
                                if (attributes != null && !attributes.isEmpty()) {
                                    List<String> phoneNumberVerified = attributes.get("phoneNumberVerified");
                                    return phoneNumberVerified != null && phoneNumberVerified.contains(Boolean.TRUE.toString());
                                }
                                return false;
                            }).collect(Collectors.toList());
                    if (userModelList.size() > 1) {
                        String error = "手机号信息错误(重复)，请联系管理员配置。";
                        logger.warn(error + ":" + phoneNumber);
                        context.getEvent().error(error);
                        Response challenge = context.form()
                                .setError(error)
                                .createErrorPage(Response.Status.CONFLICT);
                        context.failure(AuthenticationFlowError.INVALID_USER, challenge);
                        return;
                    } else if (userModelList.size() == 1) {
                        userModel = userModelList.get(0);
                        break;
                    }
                }
            }
        }
        context.getAuthenticationSession().setAuthNote(ATTEMPTED_PHONENUMBER, phoneNumber);
        if (userModel == null) {
            String error = "该手机号未绑定或未验证";
            event.clone()
                    .detail(Details.USERNAME, phoneNumber)
                    .error(error);
            logger.warn(error + ":" + phoneNumber);
            Response challenge = context.form()
                    .setError(error)
                    .createErrorPage(Response.Status.NOT_FOUND);
            context.clearUser();
            context.failure(AuthenticationFlowError.INVALID_USER, challenge);
        } else if (!userModel.isEnabled()) {
            event.clone()
                    .detail(Details.USERNAME, phoneNumber)
                    .user(userModel).error(Errors.USER_DISABLED);
            context.clearUser();
            Response challenge = context.form()
                    .setError("用户已禁用")
                    .createErrorPage(Response.Status.NOT_FOUND);
            context.clearUser();
            context.failure(AuthenticationFlowError.USER_DISABLED, challenge);
        } else {
            context.setUser(userModel);
            context.success();
        }
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Choose User Tdua";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }


    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>(1);

    static {
        ProviderConfigProperty property = new ProviderConfigProperty();
        property.setName(USER_PHONE_ATTR);
        property.setLabel("用户手机号码属性");
        property.setType(ProviderConfigProperty.MULTIVALUED_STRING_TYPE);
        List<String> attrs = new ArrayList<>(5);
        attrs.add(ATTEMPTED_PHONENUMBER);
        attrs.add("MOBILE");
        property.setDefaultValue(attrs);
        property.setHelpText("用户属性中作为手机号码的字段");
        CONFIG_PROPERTIES.add(property);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }
}
