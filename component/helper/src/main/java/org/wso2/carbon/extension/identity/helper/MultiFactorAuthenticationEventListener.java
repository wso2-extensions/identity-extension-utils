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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.extension.identity.helper.util.IdentityHelperUtil;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.IdentityErrorMsgContext;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.mgt.IdentityMgtConfig;
import org.wso2.carbon.identity.mgt.dto.UserIdentityClaimsDO;
import org.wso2.carbon.identity.mgt.store.UserIdentityDataStore;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

/**
 * Event lister for handling number of failed attempts when applying the code.
 */
public class MultiFactorAuthenticationEventListener {

    private static Log log = LogFactory.getLog(MultiFactorAuthenticationEventListener.class);
    private UserIdentityDataStore module;

    public MultiFactorAuthenticationEventListener() {
        module = IdentityMgtConfig.getInstance().getIdentityDataStore();
    }

    /**
     * This method checks if the user account exist or is locked.
     */
    public void doPreApplyCode(String userName, AuthenticationContext context)
            throws org.wso2.carbon.user.api.UserStoreException, AuthenticationFailedException {
        if (IdentityHelperUtil.isMultiFactorAuthenticationPolicyEnable(context)) {
            boolean isUserExistInCurrentDomain = FederatedAuthenticatorUtil.isUserExistInUserStore(userName);
            if (!isUserExistInCurrentDomain) {
                IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext
                        (UserCoreConstants.ErrorCode.USER_DOES_NOT_EXIST);
                IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);
                if (log.isDebugEnabled()) {
                    log.debug("Username :" + userName + "does not exists in the system, ErrorCode :"
                            + UserCoreConstants.ErrorCode.USER_DOES_NOT_EXIST);
                }
                if (IdentityHelperUtil.isMultiFactorAuthenticationPolicyEnable(context)) {
                    throw new UserStoreException(UserCoreConstants.ErrorCode.USER_DOES_NOT_EXIST);
                }
            } else {
                UserIdentityClaimsDO userIdentityDTO = module.load(userName, getUserStoreManager(userName));
                if (userIdentityDTO != null) {
                    // if the account is locked, should not be able to log in
                    if (userIdentityDTO.isAccountLocked()) {
                        // If unlock time is specified then unlock the account.
                        if ((userIdentityDTO.getUnlockTime() != 0) && (System.currentTimeMillis()
                                >= userIdentityDTO.getUnlockTime())) {
                            userIdentityDTO.setAccountLock(false);
                            userIdentityDTO.setUnlockTime(0);
                            try {
                                module.store(userIdentityDTO, getUserStoreManager(userName));
                            } catch (IdentityException e) {
                                throw new UserStoreException(
                                        "Error while saving user store data for user : " + userName, e);
                            }
                        } else {
                            IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(
                                    UserCoreConstants.ErrorCode.USER_IS_LOCKED,
                                    userIdentityDTO.getFailAttempts(),
                                    IdentityHelperUtil
                                            .getMultiFactorAuthenticationPolicyAccountLockOnFailureMaxAttempts(context));
                            IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);
                            String errorMsg = "User account is locked for user : " + userName
                                    + ". cannot login until the account is unlocked ";
                            log.warn(errorMsg);
                            throw new UserStoreException(UserCoreConstants.ErrorCode.USER_IS_LOCKED + " " + errorMsg);
                        }
                    }
                }
            }
        }
    }


    /**
     * This method locks the accounts after a configured number of
     * applying wrong code attempts. And unlocks accounts based on successful
     * authentications.
     */
    public void doPostApplyCode(String userName, boolean authenticated,
                                AuthenticationContext context) throws org.wso2.carbon.user.api.UserStoreException,
            AuthenticationFailedException {
        boolean isUserExistInCurrentDomain = FederatedAuthenticatorUtil.isUserExistInUserStore(userName);
        org.wso2.carbon.user.core.UserStoreManager userStoreManager = null;
        userStoreManager = (org.wso2.carbon.user.core.UserStoreManager)
                getUserStoreManager(userName);
        if (authenticated && isUserExistInCurrentDomain) {
            userStoreManager.setUserClaimValue(userName.substring(0, userName.lastIndexOf("@")),
                    IdentityHelperConstants.LAST_APPLY_CODE_TIME,
                    Long.toString(System.currentTimeMillis()), IdentityHelperConstants.DEFAULT);
        }
        if (IdentityHelperUtil.isMultiFactorAuthenticationPolicyEnable(context)) {
            UserIdentityClaimsDO userIdentityDTO = module.load(userName, getUserStoreManager(userName));
            if (userIdentityDTO == null) {
                userIdentityDTO = new UserIdentityClaimsDO(userName);
                userIdentityDTO.setTenantId(getUserStoreManager(userName).getTenantId());
            }
            if (!authenticated && IdentityHelperUtil.
                    isMultiFactorAuthenticationPolicyAccountLockOnFailure(context)) {
                // reading the max allowed #of failure attempts
                if (isUserExistInCurrentDomain) {
                    userIdentityDTO.setFailAttempts();
                    if (userIdentityDTO.getFailAttempts() >= IdentityHelperUtil
                            .getMultiFactorAuthenticationPolicyAccountLockOnFailureMaxAttempts(context)) {
                        log.info("User, " + userName + " has exceed the max applied code attempts. " +
                                "User account would be locked");
                        IdentityErrorMsgContext customErrorMessageContext =
                                new IdentityErrorMsgContext(UserCoreConstants.ErrorCode.USER_IS_LOCKED,
                                        userIdentityDTO.getFailAttempts(), IdentityHelperUtil
                                        .getMultiFactorAuthenticationPolicyAccountLockOnFailureMaxAttempts(context));
                        IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);

                        if (log.isDebugEnabled()) {
                            log.debug("Username :" + userName + "Exceeded the maximum apply code attempts. " +
                                    "User locked, ErrorCode :" + UserCoreConstants.ErrorCode.USER_IS_LOCKED);
                        }

                        userIdentityDTO.setAccountLock(true);
                        userIdentityDTO.setFailAttempts(0);
                        // lock time from the config
                        int lockTime = IdentityHelperUtil.getMultiFactorAuthenticationPolicyAccountLockTime(context);
                        if (lockTime != 0) {
                            userIdentityDTO.setUnlockTime(System.currentTimeMillis() +
                                    (lockTime * 60 * 1000L));
                        }
                    } else {
                        IdentityErrorMsgContext customErrorMessageContext =
                                new IdentityErrorMsgContext(UserCoreConstants.ErrorCode.INVALID_CREDENTIAL,
                                        userIdentityDTO.getFailAttempts(), IdentityHelperUtil
                                        .getMultiFactorAuthenticationPolicyAccountLockOnFailureMaxAttempts(context));
                        IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);

                        if (log.isDebugEnabled()) {
                            log.debug("Username :" + userName + "Invalid Credential, ErrorCode :"
                                    + UserCoreConstants.ErrorCode.INVALID_CREDENTIAL);
                        }
                    }
                    try {
                        module.store(userIdentityDTO, getUserStoreManager(userName));
                    } catch (IdentityException e) {
                        throw new UserStoreException("Error while saving user store data for user : "
                                + userName, e);
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("User, " + userName + " is not exists in ");
                    }
                }
            } else {
                // if the account was locked due to account verification process,
                // the unlock the account and reset the number of failedAttempts
                if (userIdentityDTO.isAccountLocked() || userIdentityDTO.getFailAttempts() > 0 || userIdentityDTO.getAccountLock()) {
                    userIdentityDTO.setAccountLock(false);
                    userIdentityDTO.setFailAttempts(0);
                    userIdentityDTO.setUnlockTime(0);
                    try {
                        module.store(userIdentityDTO, getUserStoreManager(userName));
                    } catch (IdentityException e) {
                        throw new UserStoreException("Error while saving user store data for user : "
                                + userName, e);
                    }
                }
            }
        }
    }

    /**
     * Check weather given federated username is in the local user store or not.
     *
     * @param username the username
     * @return boolean value
     */
    public org.wso2.carbon.user.api.UserStoreManager getUserStoreManager(String username) throws AuthenticationFailedException,
            org.wso2.carbon.user.api.UserStoreException {
        UserRealm userRealm;
        String tenantDomain = MultitenantUtils.getTenantDomain(username);
        int tenantID = IdentityTenantUtil.getTenantId(tenantDomain);
        RealmService realmService = IdentityTenantUtil.getRealmService();
        try {
            userRealm = realmService.getTenantUserRealm(tenantID);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new AuthenticationFailedException("Error occurred while loading user manager from user realm", e);
        }
        if (userRealm != null) {
            return userRealm.getUserStoreManager();
        }
        return null;
    }
}
