/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
public class RSASecurIdAuthenticatorConstants {
    public static final String AUTHENTICATOR_NAME = "RSASecurId";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "RSASecurIdAuthenticator";
    //RSASecurId authorize endpoint URL
    public static final String RSASecurId_OAUTH_ENDPOINT = "";
    //RSASecurId token  endpoint URL
    public static final String RSASecurId_TOKEN_ENDPOINT = "";
    //RSASecurId user info endpoint URL
    public static final String RSASecurId_USERINFO_ENDPOINT = "";
    public static final String RSA_ID = "http://wso2.org/claims/identity/rsaUserId";
    public static final String LOGIN_ENDPOINT = "securidauthenticationendpoint/login.jsp";

    public static final String RSA_USER_TOKEN = "code";

    public static final String RSA_PROPERTIES_FILE = "rsa.properties";
    private static final String ACCESS_DENIED = "Access Denied";
}