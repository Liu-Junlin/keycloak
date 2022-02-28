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
import cn.tdsj.keycloak.authentication.authenticators.resetcred.jpa.BaseEntity;
import cn.tdsj.keycloak.authentication.authenticators.resetcred.jpa.TduaEmailMessage;
import cn.tdsj.keycloak.authentication.authenticators.resetcred.util.ConfigUtil;
import cn.tdsj.keycloak.authentication.authenticators.resetcred.util.JpaUtil;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.actiontoken.DefaultActionTokenKey;
import org.keycloak.authentication.actiontoken.resetcred.ResetCredentialsActionToken;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.common.util.Time;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.*;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionCompoundId;
import org.keycloak.sessions.AuthenticationSessionModel;

import javax.persistence.EntityManager;
import javax.persistence.Query;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class ResetCredentialEmail implements Authenticator, AuthenticatorFactory {

    private static final Logger logger = Logger.getLogger(ResetCredentialEmail.class);

    private static final String PROVIDER_ID = "reset-credential-email-tdua";
    private static final String EMAIL_SEND_RATE_TEN_MINUTES = "EMAIL_SEND_RATE_TEN_MINUTES";
    private static final int DEFAULT_RATE_TEN_MINUTES = 5;

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();
        String username = authenticationSession.getAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME);
        if (!RegexConst.EMAIL_PATTERN.matcher(username).matches()) {
            String error = "邮箱格式不正确。";
            context.getEvent().error(error);
            Response challenge = context.form()
                    .setError(error)
                    .createErrorPage(Response.Status.BAD_REQUEST);
            context.failure(AuthenticationFlowError.INVALID_USER, challenge);
            return;
        }
        TduaEmailMessage tduaEmailMessage = new TduaEmailMessage();

        tduaEmailMessage.setEmail(username);
        tduaEmailMessage.setId(KeycloakModelUtils.generateId());
        tduaEmailMessage.setRealmId(context.getRealm().getId());
        tduaEmailMessage.setMessageType(BaseEntity.MessageType.CREDENTIAL_RESET);
        tduaEmailMessage.setSendTime(System.currentTimeMillis());
        int validSend = validHistorySend(context, username);
        if (validSend > 0) {
            int rateConfig = ConfigUtil.getConfig(context, EMAIL_SEND_RATE_TEN_MINUTES, DEFAULT_RATE_TEN_MINUTES);
            if (rateConfig <= 0) {
                rateConfig = DEFAULT_RATE_TEN_MINUTES;
            }
            if (validSend > rateConfig) {
                String error = "您的操作过于频繁，请稍候再试。";
                context.getEvent().error(error);
                Response challenge = context.form()
                        .setError(error)
                        .createErrorPage(Response.Status.BAD_REQUEST);
                context.failure(AuthenticationFlowError.INTERNAL_ERROR, challenge);
                JpaUtil.getEntityManager(context).persist(tduaEmailMessage);
                return;
            }
        }

        // we don't want people guessing usernames, so if there was a problem obtaining the user, the user will be null.
        // just reset login for with a success message
        if (user == null) {
            context.forkWithSuccessMessage(new FormMessage(Messages.EMAIL_SENT));
            JpaUtil.getEntityManager(context).persist(tduaEmailMessage);
            return;
        }
        tduaEmailMessage.setReceiverUserId(user.getId());
        tduaEmailMessage.setEmail(user.getEmail());

        String actionTokenUserId = authenticationSession.getAuthNote(DefaultActionTokenKey.ACTION_TOKEN_USER_ID);
        if (actionTokenUserId != null && Objects.equals(user.getId(), actionTokenUserId)) {
            logger.debugf("Forget-password triggered when reauthenticating user after authentication via action token. Skipping " + PROVIDER_ID + " screen and using user '%s' ", user.getUsername());
            context.success();
            return;
        }

        EventBuilder event = context.getEvent();
        // we don't want people guessing usernames, so if there is a problem, just continuously challenge
        if (user.getEmail() == null || user.getEmail().trim().length() == 0) {
            event.user(user)
                    .detail(Details.EMAIL, username)
                    .error(Errors.INVALID_EMAIL);

            context.forkWithSuccessMessage(new FormMessage(Messages.EMAIL_SENT));
            return;
        }

        int validityInSecs = context.getRealm().getActionTokenGeneratedByUserLifespan(ResetCredentialsActionToken.TOKEN_TYPE);
        int absoluteExpirationInSecs = Time.currentTime() + validityInSecs;

        // We send the secret in the email in a link as a query param.
        String authSessionEncodedId = AuthenticationSessionCompoundId.fromAuthSession(authenticationSession).getEncodedId();
        ResetCredentialsActionToken token = new ResetCredentialsActionToken(user.getId(), user.getEmail(), absoluteExpirationInSecs, authSessionEncodedId, authenticationSession.getClient().getClientId());
        String link = UriBuilder
                .fromUri(context.getActionTokenUrl(token.serialize(context.getSession(), context.getRealm(), context.getUriInfo())))
                .build()
                .toString();
        long expirationInMinutes = TimeUnit.SECONDS.toMinutes(validityInSecs);
        tduaEmailMessage.setSendContent(link);
        tduaEmailMessage.setSendTime(System.currentTimeMillis());
        try {
            context.getSession().getProvider(EmailTemplateProvider.class).setRealm(context.getRealm()).setUser(user).setAuthenticationSession(authenticationSession).sendPasswordReset(link, expirationInMinutes);

            event.clone().event(EventType.SEND_RESET_PASSWORD)
                    .user(user)
                    .detail(Details.USERNAME, username)
                    .detail(Details.EMAIL, user.getEmail())
                    .detail(Details.CODE_ID, authenticationSession.getParentSession().getId()).success();
            context.forkWithSuccessMessage(new FormMessage(Messages.EMAIL_SENT));
            tduaEmailMessage.setSuccess(true);
        } catch (EmailException e) {
            event.clone().event(EventType.SEND_RESET_PASSWORD)
                    .detail(Details.USERNAME, username)
                    .detail(Details.EMAIL, user.getEmail())
                    .user(user)
                    .error(Errors.EMAIL_SEND_FAILED);
            ServicesLogger.LOGGER.failedToSendPwdResetEmail(e);
            Response challenge = context.form()
                    .setError(Messages.EMAIL_SENT_ERROR)
                    .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR);
            context.failure(AuthenticationFlowError.INTERNAL_ERROR, challenge);
            tduaEmailMessage.setSuccess(false);
            tduaEmailMessage.setSendResult(e.getMessage());
        }
        JpaUtil.getEntityManager(context).persist(tduaEmailMessage);
    }

    /**
     * 查询十分钟内已发送成功的次数
     *
     * @param context 上下文信息
     * @param email   收件人地址
     * @return 十分钟内已发送成功的次数
     */
    private int validHistorySend(AuthenticationFlowContext context, String email) {
        EntityManager entityManager = JpaUtil.getEntityManager(context);
        String sql = "select count(t) from TduaEmailMessage t where realmId = ?1 and email=?2 and sendTime>= ?3";
        Query query = entityManager.createQuery(sql);
        query.setParameter(1, context.getRealm().getId());
        query.setParameter(2, email);
        query.setParameter(3, System.currentTimeMillis() - 60 * 10 * 1000);
        return Math.toIntExact((Long) query.getSingleResult());
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        context.getUser().setEmailVerified(true);
        context.success();
    }

    @Override
    public boolean requiresUser() {
        return false;
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
        return "Send Reset Email Tdua";
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
        return "Send email to user and wait for response.";
    }

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>(1);

    static {
        ProviderConfigProperty property = new ProviderConfigProperty();
        property.setName(EMAIL_SEND_RATE_TEN_MINUTES);
        property.setLabel("十分钟内最多发送次数");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setDefaultValue("5");
        property.setHelpText("十分钟最多发送次数，超过此数值，将被要求稍候再试。默认:" + DEFAULT_RATE_TEN_MINUTES);
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

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
