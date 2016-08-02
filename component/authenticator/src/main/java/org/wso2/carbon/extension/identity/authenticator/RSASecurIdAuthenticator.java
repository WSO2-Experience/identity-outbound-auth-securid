/*
 *  Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.extension.identity.authenticator;
import com.rsa.authagent.authapi.AuthAgentException;
import com.rsa.authagent.authapi.AuthSession;
import com.rsa.authagent.authapi.AuthSessionFactory;
import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.common.model.Property;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.CarbonUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Authenticator of RSASecurId
 */
public class RSASecurIdAuthenticator extends AbstractApplicationAuthenticator
        implements LocalApplicationAuthenticator {

    private static Log log = LogFactory.getLog(RSASecurIdAuthenticator.class);

    /**
     * Get the friendly name of the Authenticator
     */
    @Override
    public String getFriendlyName() {
        return RSASecurIdAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public boolean canHandle(HttpServletRequest httpServletRequest) {

        if (log.isDebugEnabled()) {
            log.debug("Inside SecurIdAuthenticator.canHandle()");
        }
        return (StringUtils.isNotEmpty(httpServletRequest.
                getParameter(RSASecurIdAuthenticatorConstants.RSA_USER_TOKEN)));
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext authenticationContext)
            throws AuthenticationFailedException {
        AuthenticatedUser authenticatedUser = getUsername(authenticationContext);
        String username = authenticatedUser.getAuthenticatedSubjectIdentifier();
        String rsaLoginPage;
        if (authenticatedUser == null) {
            throw new AuthenticationFailedException
                    ("Authentication failed!. Cannot proceed further without identifying the user");
        }
        try {
            rsaLoginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                    .replace("authenticationendpoint/login.do", RSASecurIdAuthenticatorConstants.LOGIN_ENDPOINT);
            Map<String, String> authenticatorProperties = authenticationContext
                    .getAuthenticatorProperties();
            String queryParams = FrameworkUtils
                    .getQueryStringWithFrameworkContextId(authenticationContext.getQueryParams(),
                            authenticationContext.getCallerSessionKey(),
                            authenticationContext.getContextIdentifier());
            response.sendRedirect(response.encodeRedirectURL(rsaLoginPage
                    + "?" + queryParams ));
            if (log.isDebugEnabled()) {
                log.debug("Request send to " + rsaLoginPage);
            }
            authenticationContext.setCurrentAuthenticator(getName());
        } catch (IOException e) {
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
    }

    /**
     * Get the username from authentication context.
     *
     * @param authenticationContext the authentication context
     */
    private AuthenticatedUser getUsername(AuthenticationContext authenticationContext) {
        AuthenticatedUser authenticatedUser = null;
        for (int i = 1; i <= authenticationContext.getSequenceConfig().getStepMap().size(); i++) {
            StepConfig stepConfig = authenticationContext.getSequenceConfig().getStepMap().get(i);
            if (stepConfig.getAuthenticatedUser() != null && stepConfig.getAuthenticatedAutenticator()
                    .getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
                authenticatedUser = stepConfig.getAuthenticatedUser();
                break;
            }
        }
        return authenticatedUser;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest httpServletRequest) {
        return null;
    }

    /**
     * Get the name of the Authenticator
     */
    @Override
    public String getName() {
        return RSASecurIdAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationContext authenticationContext) throws AuthenticationFailedException {
        AuthenticatedUser authenticatedUser = getUsername(authenticationContext);
        String username = authenticatedUser.getAuthenticatedSubjectIdentifier();
        String tenantDomain = authenticatedUser.getTenantDomain();
        String userStoreDomain = authenticatedUser.getUserStoreDomain();
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        RealmService realmService = IdentityTenantUtil.getRealmService();
        UserRealm userRealm;
        UserStoreManager userStoreManager;
        try {
            userRealm = realmService.getTenantUserRealm(tenantId);
            userStoreManager = (UserStoreManager) userRealm.getUserStoreManager();
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Error occurred while loading user realm or user store manager : " + e.getMessage());
        }

        AuthSessionFactory api = null;
        String userId = getUsername(authenticationContext).getAuthenticatedSubjectIdentifier();

        String passCode = httpServletRequest.getParameter(RSASecurIdAuthenticatorConstants.RSA_USER_TOKEN);
        if (StringUtils.isNotEmpty(userId) && StringUtils.isNotEmpty(passCode)) {
            try {
                String configPath = CarbonUtils.getCarbonConfigDirPath() + File.separator
                        + "identity" + File.separator;
                configPath = configPath + RSASecurIdAuthenticatorConstants.RSA_PROPERTIES_FILE;
                api = AuthSessionFactory.getInstance(configPath);
                AuthSession session;
                session = api.createUserSession();
                int authStatus = AuthSession.ACCESS_DENIED;
                authStatus = session.lock(userId);
                authStatus = session.check(userId, passCode);
                session.close();
                if (authStatus == AuthSession.ACCESS_OK) {
                    authenticationContext.setSubject(AuthenticatedUser
                            .createLocalAuthenticatedUserFromSubjectIdentifier(userId));
                }

            } catch (AuthAgentException e) {
                throw new AuthenticationFailedException("Cannot Create the API : " + e.getMessage());
            }finally {
                if(api != null)
                    try {
                        api.shutdown();
                    } catch (AuthAgentException e) {
                        throw new AuthenticationFailedException("Could not able to shut downn the API : " +  e.getMessage());
                    }
            }
        } else {
            throw new AuthenticationFailedException("UserID & Password are Empty");
        }
    }

    
}