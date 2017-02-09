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

public class IdentityHelperConstants {
    public static final String TENANT_DOMAIN_COMBINER = "@";
    public static final String SUPER_TENANT_DOMAIN = "carbon.super";
    public static final String GET_PROPERTY_FROM_REGISTRY = "getPropertiesFromLocal";
    public static final String REGISTRY_PATH = "application-authentication.xml";
    public static final String AUTHENTICATION = "authentication";
    public static final String SECONDARY_USER_STORE = "secondaryUserstore";
    public static final String USER_ATTRIBUTE = "userAttribute";
    public static final String USE_CASE = "usecase";
    public static final String IDP_NAME = "idpName";
    public static final String FIRST_USECASE = "local";
    public static final String SECOND_USECASE = "association";
    public static final String THIRD_USECASE = "userAttribute";
    public static final String FOUTH_USECASE = "subjectUri";
    public static final String ENABLE_SECOND_STEP = "enableSecondStep";
    public static final String AUTHENTICATION_CONFIG = "AuthenticatorConfig";
    public static final String NAME = "name";
    public static final String ASSOCIATION_QUERY = "SELECT USER_NAME FROM IDN_ASSOCIATED_ID WHERE TENANT_ID = ? " +
            "AND IDP_ID = (SELECT ID FROM IDP WHERE NAME = ? AND TENANT_ID = ?) AND IDP_USER_ID = ?";
    public static final String LAST_APPLY_CODE_TIME = "http://wso2.org/claims/identity/lastApplyCodeTime";
    public static final String DEFAULT = "default";
    public static final String USER_NAME = "username";
    public static final String AUTHENTICATE_USER = "authenticatedUser";

    public static final String AUTHENTICATION_POLICY_ENABLED = "authenticationPolicyEnable";
    public static final String AUTHENTICATION_POLICY_ACCOUNT_LOCK_ON_FAILURE = "authenticationPolicyAccountLockOnFailure";
    public static final String AUTHENTICATION_POLICY_ACCOUNT_LOCK_ON_FAILURE_MAS_ATTEMPTS
            = "authenticationPolicyAccountLockOnFailureMaxAttempts";
    public static final String AUTHENTICATION_POLICY_ACCOUNT_LOCK_TIME = "authenticationPolicyAccountLockTime";
}