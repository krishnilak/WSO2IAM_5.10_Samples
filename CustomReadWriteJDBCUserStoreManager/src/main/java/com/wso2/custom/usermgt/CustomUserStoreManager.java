package com.wso2.custom.usermgt;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jasypt.util.password.StrongPasswordEncryptor;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.jdbc.UniqueIDJDBCUserStoreManager;
import org.wso2.carbon.user.core.profile.ProfileConfigurationManager;
import java.sql.*;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Map;
import org.wso2.carbon.user.core.common.AuthenticationResult;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.common.FailureReason;
import org.wso2.carbon.user.core.util.DatabaseUtil;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.user.core.jdbc.JDBCRealmConstants;
import org.wso2.carbon.utils.Secret;
import org.wso2.carbon.user.core.jdbc.caseinsensitive.JDBCCaseInsensitiveConstants;

/**
 * Custom user store manager which uses 'jasypt' third party library to hash passwords */


public class CustomUserStoreManager extends UniqueIDJDBCUserStoreManager {
    private static Log log = LogFactory.getLog(CustomUserStoreManager.class);
    // This instance is used to generate the hash values
    private static StrongPasswordEncryptor passwordEncryptor = new StrongPasswordEncryptor();

    // You must implement at least one constructor
    public CustomUserStoreManager(RealmConfiguration realmConfig, Map<String, Object> properties, ClaimManager
            claimManager, ProfileConfigurationManager profileManager, UserRealm realm, Integer tenantId)
            throws UserStoreException {
        super(realmConfig, properties, claimManager, profileManager, realm, tenantId);
        log.info("CustomUserStoreManager initialized...");
    }

    @Override
    public AuthenticationResult doAuthenticateWithID(String preferredUserNameProperty, String preferredUserNameValue,
                                                     Object credential, String profileName) throws UserStoreException {

        // If the user is trying to authenticate with username.
        if (preferredUserNameProperty.equals(getUserNameMappedAttribute())) {
            return doAuthenticateWithUserName(preferredUserNameValue, credential);
        }

        AuthenticationResult authenticationResult = new AuthenticationResult(
                AuthenticationResult.AuthenticationStatus.FAIL);
        User user;

        if (!isValidCredentials(credential)) {
            String reason = "Password validation failed";
            if (log.isDebugEnabled()) {
                log.debug(reason);
            }
            return getAuthenticationResult(reason);
        }

        // add the properties
        if (profileName == null) {
            profileName = UserCoreConstants.DEFAULT_PROFILE;
        }

        Connection dbConnection = null;
        ResultSet rs = null;
        PreparedStatement prepStmt = null;
        String sqlstmt;
        String password;
        boolean isAuthed = false;

        try {

            dbConnection = getDBConnection();
            dbConnection.setAutoCommit(false);

//            if (isCaseSensitiveUsername()) {
                sqlstmt = realmConfig.getUserStoreProperty(JDBCRealmConstants.SELECT_USER_WITH_ID);
//            } else {
//                sqlstmt = realmConfig
//                        .getUserStoreProperty(JDBCCaseInsensitiveConstants.SELECT_USER_WITH_ID_CASE_INSENSITIVE);
//            }

            if (log.isDebugEnabled()) {
                log.debug(sqlstmt);
            }

            prepStmt = dbConnection.prepareStatement(sqlstmt);
            prepStmt.setString(1, preferredUserNameProperty);
            prepStmt.setString(2, preferredUserNameValue);
            prepStmt.setString(3, profileName);
            if (sqlstmt.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                prepStmt.setInt(4, tenantId);
                prepStmt.setInt(5, tenantId);
            }

            rs = prepStmt.executeQuery();

            int count = 0;
            while (rs.next()) {
                // Handle multiple matching users.
                count++;
                if (count > 1) {
                    String reason = "Invalid scenario. Multiple users found for the given username property: "
                            + preferredUserNameProperty + " and value: " + preferredUserNameValue;
                    if (log.isDebugEnabled()) {
                        log.debug(reason);
                    }
                    return getAuthenticationResult(reason);
                }

                String userID = rs.getString(1);
                String userName = rs.getString(2);
                String storedPassword1 = rs.getString(3);
                String saltValue1 = null;
                if ("true".equalsIgnoreCase(
                        realmConfig.getUserStoreProperty(JDBCRealmConstants.STORE_SALTED_PASSWORDS))) {
                    saltValue1 = rs.getString(4);
                }

                boolean requireChange = rs.getBoolean(5);
                Timestamp changedTime = rs.getTimestamp(6);

                GregorianCalendar gc = new GregorianCalendar();
                gc.add(GregorianCalendar.HOUR, -24);
                Date date = gc.getTime();

                if (requireChange && changedTime.before(date)) {
                    isAuthed = false;
                    authenticationResult = new AuthenticationResult(AuthenticationResult.AuthenticationStatus.FAIL);
                    authenticationResult.setFailureReason(new FailureReason("Password change required."));
                } else {

                    password = preparePassword(credential, saltValue1);
                    boolean passwordMatching = passwordEncryptor.checkPassword(storedPassword1,password);
                    boolean isAuthenticated=(storedPassword1 != null) && (passwordMatching);
                    if (isAuthenticated) {
                        isAuthed = true;
                        user = getUser(userID, userName);
                        user.setPreferredUsername(preferredUserNameProperty);
                        authenticationResult = new AuthenticationResult(
                                AuthenticationResult.AuthenticationStatus.SUCCESS);
                        authenticationResult.setAuthenticatedUser(user);
                    }
                }
            }
        } catch (SQLException e) {
            String msg =
                    "Error occurred while retrieving user authentication info for user : " + preferredUserNameValue;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException("Authentication Failure", e);
        } finally {
            DatabaseUtil.closeAllConnections(dbConnection, rs, prepStmt);
        }

        if (log.isDebugEnabled()) {
            log.debug("User " + preferredUserNameValue + " login attempt. Login success: " + isAuthed);
        }

        return authenticationResult;
    }

    @Override
    protected String preparePassword(Object password, String saltValue) throws UserStoreException {
        if (password != null) {
            String candidatePassword = String.copyValueOf(((Secret) password).getChars());
            log.info("Generating hash value using jasypt...");
            return passwordEncryptor.encryptPassword(candidatePassword);
        } else {
            log.error("Password cannot be null");
            throw new UserStoreException("Authentication Failure");
        }
    }

    @Override
    protected AuthenticationResult doAuthenticateWithUserName(String userName, Object credential)
            throws UserStoreException {

        AuthenticationResult authenticationResult = new AuthenticationResult(
                AuthenticationResult.AuthenticationStatus.FAIL);
        User user;

        // In order to avoid unnecessary db queries.
        if (!isValidUserName(userName)) {
            String reason = "Username validation failed.";
            if (log.isDebugEnabled()) {
                log.debug(reason);
            }
            return getAuthenticationResult(reason);
        }

        if (UserCoreUtil.isRegistryAnnonymousUser(userName)) {
            String reason = "Anonymous user trying to login.";
            log.error(reason);
            return getAuthenticationResult(reason);
        }

        if (!isValidCredentials(credential)) {
            String reason = "Password validation failed.";
            if (log.isDebugEnabled()) {
                log.debug(reason);
            }
            return getAuthenticationResult(reason);
        }

        Connection dbConnection = null;
        ResultSet rs = null;
        PreparedStatement prepStmt = null;
        String sqlstmt;
        String password;
        boolean isAuthed = false;

        try {
            dbConnection = getDBConnection();
            dbConnection.setAutoCommit(false);

            sqlstmt = realmConfig.getUserStoreProperty(JDBCRealmConstants.SELECT_USER_NAME);

            if (log.isDebugEnabled()) {
                log.debug(sqlstmt);
            }

            prepStmt = dbConnection.prepareStatement(sqlstmt);
            prepStmt.setString(1, userName);
            if (sqlstmt.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                prepStmt.setInt(2, tenantId);
            }

            rs = prepStmt.executeQuery();
            while (rs.next()) {
                String userID = rs.getString(1);
                String storedPassword = rs.getString(3);
                String saltValue = null;
                if ("true".equalsIgnoreCase(
                        realmConfig.getUserStoreProperty(JDBCRealmConstants.STORE_SALTED_PASSWORDS))) {
                    saltValue = rs.getString(4);
                }
                boolean requireChange1 = rs.getBoolean(5);
                Timestamp changedTime1 = rs.getTimestamp(6);

                GregorianCalendar gc1 = new GregorianCalendar();
                gc1.add(GregorianCalendar.HOUR, -24);
                Date date = gc1.getTime();

                if (requireChange1 && changedTime1.before(date)) {
                    isAuthed = false;
                    authenticationResult = new AuthenticationResult(AuthenticationResult.AuthenticationStatus.FAIL);
                    authenticationResult.setFailureReason(new FailureReason("Password change required."));
                } else {

                    boolean isAuthenticated = passwordEncryptor.checkPassword(credential.toString(),storedPassword);
                    if ((storedPassword != null) && (isAuthenticated)) {
                        isAuthed = true;
                        user = getUser(userID, userName);
                        authenticationResult = new AuthenticationResult(
                                AuthenticationResult.AuthenticationStatus.SUCCESS);
                        authenticationResult.setAuthenticatedUser(user);
                    }
                }
            }
        } catch (Exception e) {
            log.error(e.getStackTrace());
            String msg = "Error occurred while retrieving user authentication info for userName : " + userName;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException("Authentication Failure", e);
        } finally {
            DatabaseUtil.closeAllConnections(dbConnection, rs, prepStmt);
        }

        if (log.isDebugEnabled()) {
            log.debug("UserName " + userName + " login attempt. Login success: " + isAuthed);
        }
        return authenticationResult;
    }



    private AuthenticationResult getAuthenticationResult(String reason) {
        AuthenticationResult authenticationResult = new AuthenticationResult(
                AuthenticationResult.AuthenticationStatus.FAIL);
        authenticationResult.setFailureReason(new FailureReason(reason));
        return authenticationResult;
    }




}