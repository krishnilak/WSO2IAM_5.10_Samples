User Management Advance Tutorial 
Introduction
ABC insurance company uses WSO2 IAM as their Identity server. All their user information is needed to be stored in a JDBC user store and they want to use that JDBC user store as the primary user store. They also want to use a third-party(Jasypt) password encryption mechanism instead of using default password hashing for the users in the user store. 
Here we can break this down to two high-level tasks. Those are
Configuring JDBC as the primary user store. 
Adding a third party encryption mechanism to the authentication process. 

Configuring JDBC as the primary user store. 
WSO2 IAM supports configuring JDBC as a primary user store out of the box. Below are the steps to define the JDBC MySQL database as the Primary user store. 
First, create a database for the userstore. In my case, I am creating a database with the name of “userdb”
Run the mysql.sql script in the <IS_HOME>/dbscripts to create tables and populate tables in the userdb.
Navigate to <IS_HOME>/repository/conf folder and open deployment.toml file
Configure the user store type in the deployment.toml
[user_store]
type = “databse_unique_id”

Configure the database connection, here userdb is the database name. Replace database name, username, password values with your configurations.
[database.user]
url=”jdbc:mysql://localhost:3306/userdb?useSSL=false”
username=”root”
password=”root1234”
driver=”com.mysql.jdbc.Driver”

Configure the data source name. 
[realm_manager]
data_source=”WSO2USER_DB”

For more information on this please refer to the documentation.


Adding a third party encryption mechanism to the authentication process. 

Here we are trying to use a third party encryption mechanism for password encryption, this is not supported out of the box by WSO2 IAM. But the extensibility of WSO2 IAM inherited from its open-source nature makes it possible to write an extension to use such a third party password-encryption library. Let’s see how to write such an extension. 

First, create a maven application using an IDE that you are comfortable with. The following are the configurations I have given. Specify a group id and an artifact id you like.

Group Id: org.wso2.sample
Artifact Id: CustomReadOnlyJDBCUserStoreManager

Add the third-party encryption library(Jasypt) to the pom.xml

Group Id: org.jasypt
Artifact Id: jasypt
Version:1.9.2

Also, include the WSO2 carbon dependencies to the pom.xml. To get the carbon kernel version supported for your WSO2 IS pack, please see here. I have used the version 4.6.0 since it is the compatible version for WSO2 IAM 5.10.0

Group Id: org.wso2.carbon
Artifact Id: org.wso2.carbon.user.core
reVersion:4.6.0

Group Id: org.wso2.carbon
Artifact Id: org.wso2.carbon.user.api
Version:4.6.0

Group Id: org.wso2.carbon
Artifact Id: org.wso2.carbon.utils
Version:4.6.0

Also, include following to the export package and import package configurations to the build component, so that your classes will be exposed from the value specified in the export package. 

<Export-Package>
com.wso2.custom.usermgt.*
</Export-Package>
<Import-Package>
org.wso2.carbon.*, 
org.apache.commons.logging.*, 
org.osgi.framework.*
org.osgi.service.component.*,
org.jasypt.*;
</Import-Package>

Refer here for the sample pom.xml file

Create a java class in your maven project to extend and overwrite the userstore manager class. 

Package of the new class = com.wso2.custom.usermgt
Name of the new class = CustomUserStoreManager

org.wso2.carbon.user.core.jdbc.UniqueIDJDBCUserStoreManager is the user store manager class used by the WSO2 IAM 5.10.0. So we need to extend that class from our custom userstore manager class.

Since we want to encrypt the passwords with a third party library we need to override the preparePassword(Object password, String saltValue) method, and implement it to use the jasypt library to encrypt the passwords. Add some logging commands inside the method to identify the method is executed.








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


Then we need to override the doAuthenticateWithUserName(String userName, Object credential) method to authenticate users by comparing the stored password and incoming password using the tried party library. Add some logging commands inside the method to identify the method is executed.




Clean and Build the maven project executing following maven commands
mvn clean
mvn package
mvn install

Now the JAR file for the maven project must be generated within <ProjectFolder>/target directory.

Add the generated JAR to the <IS_HOME>/repository/components/dropins directory. 
Add the third-party(Jasypt) libraries you have used, and the MySQL driver JAR files to the <IS_HOME>/repository/components/lib folder. You can download the jasypt library from here.
Navigate to the <IS_HOME>/repository/conf directory. 
Edit the deployment.toml file to use the custom userstore manager class.

[user_store]
class="com.wso2.custom.usermgt.CustomUserStoreManager"


Try It

Start the WSO2 IS Server. 
In the startup, the admin user will be created in the primary user store. So you will get logs within the preparePassword method printed in the console. 
Next try to log in to the management console, using admin credentials, now you would see the doAuthenticate method is invoked. 




Special note 
If you have already started the WSO2 IAM pack before, the admin user is already created within the startup. So admin password is hashed using the default hashing method. Now if you have done the changes and try logging the application, it will give an authentication failure. So please make sure to use a fresh WSO2 IAM a pack.

	
			
			 			 			 		
				
		












