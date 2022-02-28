package cn.tdsj.keycloak.authentication.authenticators.resetcred.util;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.AuthenticatorConfigModel;

import java.util.Map;

/**
 * @author liujunlin
 * @date 2020/02/14
 */
public class ConfigUtil {
    private static final Logger logger = Logger.getLogger(ConfigUtil.class);

    public static String getConfig(AuthenticationFlowContext context, String configName, String defaultValue) {
        if (configName != null && !"".equals(configName.trim())) {
            AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
            if (authenticatorConfig != null) {
                Map<String, String> config = authenticatorConfig.getConfig();
                if (config != null) {
                    String value = config.get(configName.trim());
                    return value == null ? defaultValue : value;
                }
            }
        }
        return defaultValue;
    }

    public static boolean getConfig(AuthenticationFlowContext context, String configName, boolean defaultValue) {
        if (configName != null && !"".equals(configName.trim())) {
            AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
            if (authenticatorConfig != null) {
                Map<String, String> config = authenticatorConfig.getConfig();
                if (config != null) {
                    String value = config.get(configName.trim());
                    return Boolean.TRUE.toString().equalsIgnoreCase(value);
                }
            }
        }
        return defaultValue;
    }

    public static int getConfig(AuthenticationFlowContext context, String configName, int defaultValue) {
        if (configName != null && !"".equals(configName.trim())) {
            AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
            if (authenticatorConfig != null) {
                Map<String, String> config = authenticatorConfig.getConfig();
                if (config != null) {
                    String value = config.get(configName.trim());
                    try {
                        return Integer.parseInt(value);
                    } catch (NumberFormatException e) {
                        logger.error(configName, e);
                        return defaultValue;
                    }
                }
            }
        }
        return defaultValue;
    }
}
