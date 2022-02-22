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

package org.keycloak.authentication.authenticators.browser;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jboss.resteasy.specimpl.MultivaluedMapImpl;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.managers.AuthenticationManager;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class UsernamePasswordForm extends AbstractUsernameFormAuthenticator implements Authenticator {
    protected static ServicesLogger log = ServicesLogger.LOGGER;
    private static PrivateKey privateKey;
    private static final String PRIVATE_KEY = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAIMQMw7N5BATBoTYH/9t93CO4Qcyr0t6JLThbvv2JBTUPWr8P989PJANlROmNjXApjurVwXOqNr1JpA6AWfcSmrWQnTkp3Vc8SiecBOFY9ov5HzrDHSutPmOoQPJ+xsJufGCn4Ria6iLWhUU9RWhohp6292SmLWyZRDigcRjABzVAgMBAAECgYBXD5W7Cc2rV9gGusJWnKe3n1GfxG1pR9PGS9G7kX/aTjoWLUYIdtcaIcubZ9eu0TAbhu+hrevAtwRM3hs88LqFVfcx6nU+EqFS2OYqR/tyDNPI6X63k20EB4GOevh9wJSqLgeLoKmfMjKElkF4PgkCTIlGGOYoJubugB5vLAj6gQJBAMA7V1Rahjq9I06MPikAx2ly7c6zEG7ja+MwSXzwAcHTbG9D452ygrF3M0L4sRq9rdxoCTlisd1OWOVcU8o+EmUCQQCuilIvH/4VHenNTXCInBQONa+KMsk0RxJdd8XJzClsHCImgZ4oA2s92xR7VMLmRBjxUorXeYo94krCTQT+RwGxAkBOrfsog4S9NfzlgXFPxwnXlzrOh2wKdvsJmhH6GSIe+zI+uELJoO7tRCSvHKsgjtJCjDJ6UnMKaa7o8ck51f4hAkAXTaR3YkAcNag3nvU9aAlNdGGBhBJVBoAvNoST0sxdAMyWc4vYL8yrr4pmhQSYldL2tVyQNEv+wy3UD1BxWq2hAkBAQCySOzslTqlZqIbXhp5l6c+VBlMMu3FC+im7PvqykUMWD9+YDP7w7ON7gUpGN4yIoTj1FCBsmrTSpSzB07FE";
    private static final String ALGORITHM = "RSA";
    private static final String CIPHER_ALGORITHM = "RSA/ECB/PKCS1Padding";

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        try {
            KeyFactory factory = KeyFactory.getInstance(ALGORITHM);
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(PRIVATE_KEY.getBytes(StandardCharsets.UTF_8)));
            privateKey = factory.generatePrivate(pkcs8EncodedKeySpec);
        } catch (Exception e) {
            log.error("", e);
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("cancel")) {
            context.cancelLogin();
            return;
        }
        if (!validateForm(context, formData)) {
            return;
        }
        context.success();
    }

    protected boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        return validateCaptcha(context, formData) && decryptAndReplacePassword(context, formData) && validateUserAndPassword(context, formData);
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = new MultivaluedMapImpl<>();
        String loginHint = context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);

        String rememberMeUsername = AuthenticationManager.getRememberMeUsername(context.getRealm(), context.getHttpRequest().getHttpHeaders());

        if (context.getUser() != null) {
            LoginFormsProvider form = context.form();
            form.setAttribute(LoginFormsProvider.USERNAME_HIDDEN, true);
            form.setAttribute(LoginFormsProvider.REGISTRATION_DISABLED, true);
            context.getAuthenticationSession().setAuthNote(USER_SET_BEFORE_USERNAME_PASSWORD_AUTH, "true");
        } else {
            context.getAuthenticationSession().removeAuthNote(USER_SET_BEFORE_USERNAME_PASSWORD_AUTH);
            if (loginHint != null || rememberMeUsername != null) {
                if (loginHint != null) {
                    formData.add(AuthenticationManager.FORM_USERNAME, loginHint);
                } else {
                    formData.add(AuthenticationManager.FORM_USERNAME, rememberMeUsername);
                    formData.add("rememberMe", "on");
                }
            }
        }
        context.form().setAttribute(UsernamePasswordFormFactory.USE_CAPTCHA,isCaptchaEnable(context));
        Response challengeResponse = challenge(context, formData);
        context.challenge(challengeResponse);
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    protected Response challenge(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        LoginFormsProvider forms = context.form();

        if (formData.size() > 0) {
            forms.setFormData(formData);
        }

        return forms.createLoginUsernamePassword();
    }


    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        // never called
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // never called
    }

    @Override
    public void close() {

    }

    private boolean isCaptchaEnable(AuthenticationFlowContext context) {
        AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
        if (authenticatorConfig == null) {
            return true;
        }
        Map<String, String> config = authenticatorConfig.getConfig();
        boolean enabled = false;
        if (config != null) {
            enabled = Boolean.parseBoolean(config.getOrDefault(UsernamePasswordFormFactory.USE_CAPTCHA, "false"));
        }
        return enabled;
    }

    protected boolean validateCaptcha(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        if (!isCaptchaEnable(context)) {
            return true;
        }
        String captchaCode = context.getAuthenticationSession().getAuthNote("CAPTCHA_CODE");
        boolean match = false;
        log.debugf("AuthNote captchaCode:%s", captchaCode);
        if (captchaCode != null && !"".equals(captchaCode.trim())) {
            String captcha = formData.getFirst("captcha");
            log.debugf("formData captchaCode:%s", captcha);
            if (captcha != null && captchaCode.equalsIgnoreCase(captcha.trim())) {
                match = true;
            }
        } else {
            log.warn("AuthNote captchaCode not exists");
        }
        if (!match) {
            context.getEvent().error("验证码不正确");
            Response challengeResponse = challenge(context, "验证码不正确!");
            context.forceChallenge(challengeResponse);
            context.clearUser();
        }
        return match;
    }

    private boolean decryptAndReplacePassword(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        String password = formData.getFirst(CredentialRepresentation.PASSWORD);
        if (password != null && !password.isEmpty()) {
            try {
                password = decrypt(password);
                formData.putSingle(CredentialRepresentation.PASSWORD, password);
            } catch (Exception e) {
                String errorInfo = "密码无效，请检查您的参数，或清除浏览器缓存后尝试重新登陆";
                context.getEvent().error(errorInfo);
                Response challengeResponse = challenge(context, errorInfo);
                context.forceChallenge(challengeResponse);
                log.error(errorInfo, e);
                return false;
            }
        }
        return true;
    }

    public String decrypt(String encrypted) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decodeBytes = Base64.getDecoder().decode(encrypted.getBytes(StandardCharsets.UTF_8));
        byte[] result = cipher.doFinal(decodeBytes);
        return new String(result, StandardCharsets.UTF_8);
    }

}
