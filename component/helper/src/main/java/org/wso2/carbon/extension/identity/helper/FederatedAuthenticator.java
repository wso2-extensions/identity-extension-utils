/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.extension.identity.helper;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.extension.identity.helper.util.IdentityHelperUtil;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Federate authenticator support for multi factor authentication.
 */
public class FederatedAuthenticator {
    private static Log log = LogFactory.getLog(FederatedAuthenticator.class);

    /**
     * Get parameter values from application-authentication.xml local file.
     */
    public static Map<String, String> getAuthenticatorConfig(String authenticatorConfigEntry) {
        AuthenticatorConfig authConfig = FileBasedConfigurationBuilder.getInstance()
                .getAuthenticatorBean(authenticatorConfigEntry);
        return authConfig.getParameterMap();
    }

    /**
     * Update the authenticated user context.
     *
     * @param context           the authentication context
     * @param authenticatedUser the authenticated user's name
     */
    public void updateAuthenticatedUserInStepConfig(AuthenticationContext context,
                                                    AuthenticatedUser authenticatedUser) {
        for (Object setConfigSet : context.getSequenceConfig().getStepMap().entrySet()) {
            Map.Entry thisEntry = (Map.Entry) setConfigSet;
            StepConfig stepConfig = (StepConfig) thisEntry.getValue();
            if (stepConfig.getAuthenticatedUser() != null && stepConfig.getAuthenticatedAutenticator()
                    .getApplicationAuthenticator() instanceof FederatedApplicationAuthenticator) {
                authenticatedUser = stepConfig.getAuthenticatedUser();
                break;
            }
        }
        context.setSubject(authenticatedUser);
    }

    /**
     * Get the username from authentication context.
     *
     * @param context the authentication context
     */
    public AuthenticatedUser getUsername(AuthenticationContext context) {
        AuthenticatedUser authenticatedUser = null;
        for (Object setConfigSet : context.getSequenceConfig().getStepMap().entrySet()) {
            Map.Entry thisEntry = (Map.Entry) setConfigSet;
            StepConfig stepConfig = (StepConfig) thisEntry.getValue();
            if (stepConfig.getAuthenticatedUser() != null) {
                authenticatedUser = stepConfig.getAuthenticatedUser();
                break;
            }
        }
        return authenticatedUser;
    }

    /**
     * Check weather given federated username is in the local user store or not
     *
     * @param federatedUsername federated helper username
     * @return boolean value
     */
    public boolean isExistUserInUserStore(String federatedUsername) throws AuthenticationFailedException,
            UserStoreException {
        UserRealm userRealm;
        boolean isExistUser = false;
        String tenantDomain = MultitenantUtils.getTenantDomain(federatedUsername);
        int tenantID = IdentityTenantUtil.getTenantId(tenantDomain);
        RealmService realmService = IdentityTenantUtil.getRealmService();
        try {
            userRealm = realmService.getTenantUserRealm(tenantID);
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Error occurred while loading user manager from user realm", e);
        }
        String tenantAwareFederatedUsername = MultitenantUtils.getTenantAwareUsername(String.valueOf(federatedUsername));
        if (userRealm != null) {
            //Check the federated username is already exist or not in the user store
            try {
                isExistUser = userRealm.getUserStoreManager().isExistingUser(tenantAwareFederatedUsername);
            } catch (UserStoreException e) {
                throw new AuthenticationFailedException("Cannot find the user in User store", e);
            }
        }
        return isExistUser;
    }

    /**
     * Get local username which is associated with federated helper username.
     *
     * @param federatedUsername federated helper's username
     * @param context           the authentication context
     * @return local username
     */
    public String getLocalUsernameAssociatedWithFederatedUser(String federatedUsername,
                                                              AuthenticationContext context)
            throws AuthenticationFailedException {
        String localUsername;
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet resultSet;
        String idpName = context.getProperty(IdentityHelperConstants.IDP_NAME).toString();
        String tenantDomain = context.getTenantDomain();
        int tenantID = IdentityTenantUtil.getTenantId(tenantDomain);
        try {
            prepStmt = connection.prepareStatement(IdentityHelperConstants.ASSOCIATION_QUERY);
            prepStmt.setInt(1, tenantID);
            prepStmt.setString(2, idpName);
            prepStmt.setInt(3, tenantID);
            prepStmt.setString(4, federatedUsername);
            resultSet = prepStmt.executeQuery();
            connection.commit();
            if (resultSet.next()) {
                localUsername = resultSet.getString(1);
                return localUsername;
            }
        } catch (SQLException e) {
            throw new AuthenticationFailedException("Error occurred while getting the associated helper Username", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
        return null;
    }

    /**
     * Get list of secondary user stores
     *
     * @param context the authentication context
     */
    public List<String> listSecondaryUserStores(AuthenticationContext context) {
        List<String> userStores = null;
        String secondaryUserStore;
        secondaryUserStore = IdentityHelperUtil.getSecondaryUserStore(context);
        if (StringUtils.isNotEmpty(secondaryUserStore)) {
            userStores = Arrays.asList(secondaryUserStore.split(","));
        }
        return userStores;
    }

    /**
     * Get username from local
     *
     * @param context           the authentication context.
     * @param federatedUsername federated  username
     */
    public String getUserNameFromLocal(String federatedUsername, AuthenticationContext context)
            throws AuthenticationFailedException {
        String username = null;
        List<String> userStores;
        try {
            userStores = listSecondaryUserStores(context);
            if (userStores != null) {
                for (Object userDomain : userStores) {
                    String federatedUsernameWithDomain;
                    federatedUsernameWithDomain = IdentityUtil.addDomainToName(federatedUsername, String.valueOf(userDomain));
                    if (isExistUserInUserStore(federatedUsernameWithDomain)) {
                        username = federatedUsernameWithDomain;
                        break;
                    }
                }
            } else if (isExistUserInUserStore(federatedUsername)) {
                username = federatedUsername;
            }
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Cannot find the user in User store", e);
        }
        return username;
    }

    /**
     * Get username from association
     *
     * @param context           the authentication context.
     * @param federatedUsername federated  username
     */
    public String getUserNameFromAssociation(String federatedUsername, AuthenticationContext context)
            throws AuthenticationFailedException {
        String tenantAwareLocalUsername;
        String username;
        String tenantAwareFederatedUsername = MultitenantUtils.getTenantAwareUsername(String.valueOf(federatedUsername));
        try {
            //Get associated local username of federated helper
            tenantAwareLocalUsername = getLocalUsernameAssociatedWithFederatedUser(tenantAwareFederatedUsername, context);
            String localUsernameTenantDomain = MultitenantUtils.getTenantDomain(federatedUsername);
            username = tenantAwareLocalUsername + IdentityHelperConstants.TENANT_DOMAIN_COMBINER +
                    localUsernameTenantDomain;
            List<String> userStores;
            userStores = listSecondaryUserStores(context);
            if (userStores != null) {
                for (Object userDomain : userStores) {
                    String federatedUsernameWithDomain;
                    federatedUsernameWithDomain = IdentityUtil.addDomainToName(username, String.valueOf(userDomain));
                    if (isExistUserInUserStore(federatedUsernameWithDomain)) {
                        username = federatedUsernameWithDomain;
                        break;
                    }
                }
            }
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Error while getting secondary user stores ", e);
        }
        return username;
    }

    /**
     * Return loggedIn Federated username.
     *
     * @param context the authentication context.
     * @return federated username.
     */
    public String getLoggedInFederatedUser(AuthenticationContext context) {
        String username = "";
        for (int i = context.getSequenceConfig().getStepMap().size() - 1; i >= 0; i--) {
            if (context.getSequenceConfig().getStepMap().get(i).getAuthenticatedUser() != null &&
                    context.getSequenceConfig().getStepMap().get(i).getAuthenticatedAutenticator()
                            .getApplicationAuthenticator() instanceof FederatedApplicationAuthenticator) {
                String idpName = context.getSequenceConfig().getStepMap().get(i).getAuthenticatedIdP();
                context.setProperty(IdentityHelperConstants.IDP_NAME, idpName);
                username = context.getSequenceConfig().getStepMap().get(i).getAuthenticatedUser().toString();
                break;
            }
        }
        return username;
    }

    /**
     * Get username from federated  user attribute
     *
     * @param context the authentication context.
     */
    public String getUserNameFromUserAttributes(AuthenticationContext context)
            throws AuthenticationFailedException {
        Map<ClaimMapping, String> userAttributes;
        String username = null;
        String userAttribute;
        userAttributes = context.getCurrentAuthenticatedIdPs().values().iterator().next().getUser().getUserAttributes();
        userAttribute = IdentityHelperUtil.getUserAttribute(context);
        if (StringUtils.isNotEmpty(userAttribute)) {
            for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
                String key = String.valueOf(entry.getKey().getLocalClaim().getClaimUri());
                String value = entry.getValue();
                if (key.equals(userAttribute)) {
                    String tenantAwareUsername = String.valueOf(value);
                    String usernameTenantDomain = context.getCurrentAuthenticatedIdPs().values().iterator().
                            next().getUser().getTenantDomain();
                    username = tenantAwareUsername + IdentityHelperConstants.TENANT_DOMAIN_COMBINER +
                            usernameTenantDomain;
                    List<String> userStores;
                    userStores = listSecondaryUserStores(context);
                    if (userStores != null) {
                        for (Object userDomain : userStores) {
                            String federatedUsernameWithDomain;
                            federatedUsernameWithDomain = IdentityUtil.addDomainToName(username,
                                    String.valueOf(userDomain));
                            try {
                                if (isExistUserInUserStore(federatedUsernameWithDomain)) {
                                    username = federatedUsernameWithDomain;
                                    break;
                                }
                            } catch (UserStoreException e) {
                                throw new AuthenticationFailedException("Error while getting secondary user stores ", e);
                            }
                        }
                    }
                    break;
                }
            }
        }
        if (StringUtils.isEmpty(username)) {
            StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(context.getCurrentStep() - 1);
            String previousStepAuthenticator = stepConfig.getAuthenticatedAutenticator().getName();
            Map<String, String> parametersMap = getAuthenticatorConfig(previousStepAuthenticator);
            StepConfig currentStep = context.getSequenceConfig().getStepMap().get(context.getCurrentStep());
            String currentStepAuthenticator = currentStep.getAuthenticatorList().iterator().next().getName();
            userAttribute = parametersMap.get(currentStepAuthenticator + IdentityHelperConstants.HYPHEN +
                    IdentityHelperConstants.THIRD_USECASE);
            if (StringUtils.isNotEmpty(userAttribute)) {
                for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
                    String key = String.valueOf(entry.getKey().getLocalClaim().getClaimUri());
                    String value = entry.getValue();
                    if (key.equals(userAttribute)) {
                        String tenantAwareUsername = String.valueOf(value);
                        String usernameTenantDomain = context.getCurrentAuthenticatedIdPs().values().iterator().
                                next().getUser().getTenantDomain();
                        username = tenantAwareUsername + IdentityHelperConstants.TENANT_DOMAIN_COMBINER +
                                usernameTenantDomain;
                        List<String> userStores;
                        userStores = listSecondaryUserStores(context);
                        if (userStores != null) {
                            for (Object userDomain : userStores) {
                                String federatedUsernameWithDomain;
                                federatedUsernameWithDomain = IdentityUtil.addDomainToName(username,
                                        String.valueOf(userDomain));
                                try {
                                    if (isExistUserInUserStore(federatedUsernameWithDomain)) {
                                        username = federatedUsernameWithDomain;
                                        break;
                                    }
                                } catch (UserStoreException e) {
                                    throw new AuthenticationFailedException("Error while getting secondary user stores ", e);
                                }
                            }
                        }
                        break;
                    }
                }
            }
        }
        return username;
    }

    /**
     * Get username from subjectUri of federated helper
     *
     * @param context           the authentication context.
     * @param federatedUsername federated helper's username
     */
    public String getUserNameFromSubjectURI(String federatedUsername, AuthenticationContext context)
            throws AuthenticationFailedException {
        List<String> userStores;
        String subjectAttribute = context.getCurrentAuthenticatedIdPs().values().iterator().next().
                getUser().getAuthenticatedSubjectIdentifier();
        String tenantDomain = MultitenantUtils.getTenantDomain(federatedUsername);
        String username = subjectAttribute + IdentityHelperConstants.TENANT_DOMAIN_COMBINER + tenantDomain;
        userStores = listSecondaryUserStores(context);
        try {
            if (userStores != null) {
                for (Object userDomain : userStores) {
                    String federatedUsernameWithDomain;
                    federatedUsernameWithDomain = IdentityUtil.addDomainToName(username, String.valueOf(userDomain));
                    if (isExistUserInUserStore(federatedUsernameWithDomain)) {
                        username = federatedUsernameWithDomain;
                        break;
                    }
                }
            }
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Error while getting secondary user stores ", e);
        }
        return username;
    }

    /**
     * Check the first step of helper type and get username from first step
     *
     * @param context the authentication context
     */
    public void getUsernameFromFirstStep(AuthenticationContext context) throws AuthenticationFailedException {
        String username = null;
        AuthenticatedUser authenticatedUser;
        StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(context.getCurrentStep() - 1);
        if (stepConfig.getAuthenticatedAutenticator().getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
            username = getLoggedInLocalUser(context);
            authenticatedUser = getUsername(context);
        } else {
            //Get username from federated helper
            String federatedUsername = getLoggedInFederatedUser(context);
            String usecase = IdentityHelperUtil.getUsecase(context);
            if (StringUtils.isEmpty(usecase) || IdentityHelperConstants.FIRST_USECASE.equals(usecase)) {
                username = getUserNameFromLocal(federatedUsername, context);
            }
            if (IdentityHelperConstants.SECOND_USECASE.equals(usecase)) {
                username = getUserNameFromAssociation(federatedUsername, context);
            }
            if (IdentityHelperConstants.THIRD_USECASE.equals(usecase)) {
                username = getUserNameFromUserAttributes(context);
            }
            if (IdentityHelperConstants.FOUTH_USECASE.equals(usecase)) {
                username = getUserNameFromSubjectURI(federatedUsername, context);
            }
            authenticatedUser = getUsername(context);
        }
        context.setProperty(IdentityHelperConstants.USER_NAME, username);
        context.setProperty(IdentityHelperConstants.AUTHENTICATE_USER, authenticatedUser);
    }

    /**
     * Get the user name from fist step.
     *
     * @param context the authentication context
     * @return user name
     */
    public String getLoggedInLocalUser(AuthenticationContext context) {
        String username = "";
        for (int i = context.getSequenceConfig().getStepMap().size() - 1; i >= 0; i--) {
            if (context.getSequenceConfig().getStepMap().get(i).getAuthenticatedUser() != null &&
                    context.getSequenceConfig().getStepMap().get(i).getAuthenticatedAutenticator()
                            .getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
                username = context.getSequenceConfig().getStepMap().get(i).getAuthenticatedUser().toString();
                if (log.isDebugEnabled()) {
                    log.debug("username :" + username);
                }
                break;
            }
        }
        return username;
    }

    /**
     * Update the authenticated user context.
     *
     * @param context           the authentication context
     * @param authenticatedUser the authenticated user's name
     */
    public void updateLocalAuthenticatedUserInStepConfig(AuthenticationContext context,
                                                         AuthenticatedUser authenticatedUser) {
        for (int i = 1; i <= context.getSequenceConfig().getStepMap().size(); i++) {
            StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(i);
            if (stepConfig.getAuthenticatedUser() != null && stepConfig.getAuthenticatedAutenticator()
                    .getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
                authenticatedUser = stepConfig.getAuthenticatedUser();
                break;
            }
        }
        context.setSubject(authenticatedUser);
    }
}
