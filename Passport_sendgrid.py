# oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
# Copyright (c) 2016, Gluu
#
# Author: Jogesh Krupa Dash 

# In this custom script user login should be happened either from basic authentication or through email mfa journey with resend option.
# If the isMFAEnabled option is set to true then user will be logged in with email mfa
# If the isMFAEnabled option is set to false then user will be logged in through basic authentication using credentials
# after 3 attempts of resend email, user should see the error message i.e maximum number of attempts exceeded & click on "Back to Login"
#

from org.xdi.service.cdi.util import CdiUtil
from org.gluu.jsf2.message import FacesMessages
from javax.faces.application import FacesMessage
from org.xdi.util import StringHelper, ArrayHelper
from java.util import Arrays, HashMap, IdentityHashMap
from org.xdi.oxauth.security import Identity
from org.xdi.model.custom.script.type.auth import PersonAuthenticationType
from org.xdi.oxauth.service import UserService, AuthenticationService
from org.xdi.oxauth.model.common import User
from org.xdi.util import StringHelper
from org.xdi.oxauth.util import ServerUtil
from org.gluu.jsf2.service import FacesService
from org.xdi.oxauth.model.util import Base64Util
from org.python.core.util import StringUtil
from org.xdi.oxauth.service.net import HttpService
from javax.faces.context import FacesContext

from org.xdi.oxauth.service import SessionIdService
from urlparse import urlparse


from com.sendgrid.helpers.mail.objects import Email
from com.sendgrid.helpers.mail.objects import Content 
from com.sendgrid.helpers.mail.objects import Mail 
from com.sendgrid.helpers.mail import Method, Request, Response , SendGrid
import java.io.IOException

import random
import time
import json
import java

class PersonAuthentication(PersonAuthenticationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis
        self.identity = CdiUtil.bean(Identity)

        # SMTP Connection Strings
        self.SMTP_FROM_USER = None
        self.user_email= None
        self.SendGrid_API_KEY = None

        self.userfullname = None
        self.isMFAEnabled = None
        self.maxResendOTPAttempts = 1
        self.authenticationSteps = 1
        self.client_host_uri = None
        self.isUserAuthenticated = False
    print ("Passport-social: Initialized successfully")

    def init(self, configurationAttributes):
        print ("Passport-social: Initialization init method call")
        self.extensionModule = None
        self.attributesMapping = None

        try:
                self.SendGrid_API_KEY  = configurationAttributes.get("sendgrid_api_key").getValue2()
                print("SendGrid API KEY: ",self.SendGrid_API_KEY)
        except:
                print('Email OTP, Missing required configuration attribute "sendgrid_api_key"')

        try:
                self.SMTP_FROM_USER  = configurationAttributes.get("from_user").getValue2()
                print("SMTP-FROM-USER: ",self.SMTP_FROM_USER)
        except:
                print('Email OTP, Missing required configuration attribute "from_user"')
        
        if (configurationAttributes.containsKey("generic_remote_attributes_list") and
                configurationAttributes.containsKey("generic_local_attributes_list")):

            remoteAttributesList = configurationAttributes.get("generic_remote_attributes_list").getValue2()
            if (StringHelper.isEmpty(remoteAttributesList)):
                print ("Passport-social: Initialization. The property generic_remote_attributes_list is empty")
                return False

            localAttributesList = configurationAttributes.get("generic_local_attributes_list").getValue2()
            if (StringHelper.isEmpty(localAttributesList)):
                print ("Passport-social: Initialization. The property generic_local_attributes_list is empty")
                return False

            self.attributesMapping = self.prepareAttributesMapping(remoteAttributesList, localAttributesList)
            if (self.attributesMapping == None):
                print ("Passport-social: Initialization. The attributes mapping isn't valid")
                return False

        if (configurationAttributes.containsKey("extension_module")):
            extensionModuleName = configurationAttributes.get("extension_module").getValue2()
            try:
                self.extensionModule = __import__(extensionModuleName)
                extensionModuleInitResult = self.extensionModule.init(configurationAttributes)
                if (not extensionModuleInitResult):
                    return False
            except ImportError as ex:
                print ("Passport-social: Initialization. Failed to load generic_extension_module:", extensionModuleName)
                print ("Passport-social: Initialization. Unexpected error:", ex)
                return False
        else:
            print("Passport-social: Extension module key not found")
        return True

    def destroy(self, configurationAttributes):
        print ("Passport-social: Basic. Destroy method call")
        print ("Passport-social: Basic. Destroyed successfully")
        return True

    def getApiVersion(self):
        return 1

    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        return True

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        return None

    def getUserValueFromAuth(self, remote_attr, requestParameters):
        try:
            toBeFeatched = "loginForm:" + remote_attr
            return ServerUtil.getFirstValue(requestParameters, toBeFeatched)
        except Exception as err:
            print("Passport-social: Exception inside getUserValueFromAuth " + str(err))

    def authenticate(self, configurationAttributes, requestParameters, step):
        authenticationService = CdiUtil.bean(AuthenticationService)
        sessionIdService = CdiUtil.bean(SessionIdService)
        sessionId = sessionIdService.getSessionId()
        session_attributes = self.identity.getSessionId().getSessionAttributes()
        if self.isUserAuthenticated == True:
            facesMessages = CdiUtil.bean(FacesMessages)
            facesMessages.setKeepMessages()
            facesMessages.add(FacesMessage.SEVERITY_ERROR, "User is already Authenticated")
            session_attributes.put("otpTimeLeft", "0")
            return False

        extensionResult = self.extensionAuthenticate(configurationAttributes, requestParameters, step)
        if extensionResult != None:
            return extensionResult

        try:
            UserId = self.getUserValueFromAuth("userid", requestParameters)

        except Exception as err:
            print("Passport-social: Error: " + str(err))

        if step == 1: 
            facesMessages = CdiUtil.bean(FacesMessages)
            facesMessages.setKeepMessages()
            print ("Step 1: Authenticate() executed successfully")
            useBasicAuth = False
            if (StringHelper.isEmptyString(UserId)):
                useBasicAuth = True

            # Use basic method to log in
            if (useBasicAuth):
                print ("Passport-social: Basic Authentication")
                print ("checking Basic Authentication 1")
                identity = CdiUtil.bean(Identity)
                credentials = identity.getCredentials()
                user_name = credentials.getUsername()
                user_password = credentials.getPassword()
                logged_in = False
                print ("checking Basic Authentication 2")
                if (StringHelper.isNotEmptyString(user_name) and StringHelper.isNotEmptyString(user_password)):
                    userService = CdiUtil.bean(UserService)
                    logged_in = authenticationService.authenticate(user_name, user_password)
                    print ("checking Basic Authentication 3")
                if (not logged_in):
                    return False
                
                print ("checking Basic Authentication 4")
                
                # Get the Person's number and generate a code
                foundUser = None
                firstName = ""
                lastName = ""
                try:
                    foundUser = authenticationService.getAuthenticatedUser()
                    print("foundUser ",foundUser)
                    
                    try:
                        firstName = foundUser.getAttributeValues("givenname")[0]
                        print("foundUser firstName is: ",firstName)
                    except:
                        print("foundUser firstName not found")

                    try:
                        lastName = foundUser.getAttributeValues("sn")[0]
                        print("foundUser lastName is: ",lastName)
                    except:
                        print("foundUser lastName not found")  
                    print("got user firstName & lastName")
                    self.userfullname = str(str(firstName) +" "+str(lastName))
                    print("foundUser full name is :",self.userfullname)

                    try:
                        self.isMFAEnabled = foundUser.getAttributeValues("mfaEnabled")[0]
                        print("foundUser MFA Enable Status :",self.isMFAEnabled)
                    except:
                        # by default MFA is enabled for all users
                        self.isMFAEnabled = "true"
                        print ('Email OTP, mfaEnabled Attribute not found for user %s' % (user_name))
                        
                    if(self.isMFAEnabled=="true"):
                        # print("foundUser MFA Enable Status :",self.isMFAEnabled)
                        self.authenticationSteps = 2
                        print("self.authenticationSteps --  :",self.authenticationSteps)

                except:
                    print ('Email OTP, Error retrieving user %s from LDAP' % (user_name))
                    return False
   
                try:
                    self.user_email = foundUser.getAttribute("mail")  
                    
                    print('user email is %s' % self.user_email)        
                except:
                    facesMessages.add(FacesMessage.SEVERITY_ERROR, "Failed to determine email")
                    print ('Email OTP, Error finding email for "%s". Exception: %s` % (user_name, sys.exc_info()[1])`')
                    return False
                
                if(self.isMFAEnabled=="true"):
                        session_attributes.put("client_host_uri",self.client_host_uri)
                        self.loadEmailMFAConfigs(sessionId,session_attributes)
                return True

            else:
                try:
                    facesMessages = CdiUtil.bean(FacesMessages)
                    facesMessages.setKeepMessages()
                    userService = CdiUtil.bean(UserService)
                    authenticationService = CdiUtil.bean(AuthenticationService)
                    foundUser = userService.getUserByAttribute("mail", self.getUserValueFromAuth("email", requestParameters))

                    if (foundUser == None):
                        newUser = User()

                        try:
                            UserEmail = self.getUserValueFromAuth("email", requestParameters)
                        except Exception as err:
                            print("Passport-social: Error in getting user email: " + str(err))

                        if (StringHelper.isEmptyString(UserEmail)):
                            facesMessages.add(FacesMessage.SEVERITY_ERROR, "Please provide your email.")
                            print ("Passport-social: Email was not received so sent error")
                            return False

                        for attributesMappingEntry in self.attributesMapping.entrySet():
                            remoteAttribute = attributesMappingEntry.getKey()
                            localAttribute = attributesMappingEntry.getValue()
                            localAttributeValue = self.getUserValueFromAuth(remoteAttribute, requestParameters)
                            if ((localAttribute != None) & (localAttributeValue != "undefined") & (
                                        localAttribute != "provider")):
                                newUser.setAttribute(localAttribute, localAttributeValue)

                        if "shibboleth" in self.getUserValueFromAuth("provider", requestParameters):
                            newUser.setAttribute("oxExternalUid", "passport-saml" + ":" + self.getUserValueFromAuth(self.getUidRemoteAttr(), requestParameters))
                        else:
                            newUser.setAttribute("oxExternalUid", "passport-"+ self.getUserValueFromAuth("provider",requestParameters) + ":" + self.getUserValueFromAuth(self.getUidRemoteAttr(), requestParameters))

                        print ("Passport-social: " + self.getUserValueFromAuth("provider",
                                                        requestParameters) + ": Attempting to add user " + self.getUserValueFromAuth(
                            self.getUidRemoteAttr(), requestParameters))

                        try:
                            foundUser = userService.addUser(newUser, True)
                            foundUserName = foundUser.getUserId()
                            print("Passport-social: Found user name " + foundUserName)
                            userAuthenticated = authenticationService.authenticate(foundUserName)
                            print("Passport-social: User added successfully and isUserAuthenticated = " + str(userAuthenticated))
                        except Exception as err:
                            print("Passport-social: Error in adding user:" + str(err))
                            return False
                        return userAuthenticated

                    else:
                        foundUserName = foundUser.getUserId()
                        print("Passport-social: YYY: " + str(foundUser))
                        print("Passport-social: User Found " + str(foundUserName))
                        userService = CdiUtil.bean(UserService)

                        for attributesMappingEntry in self.attributesMapping.entrySet():
                            remoteAttribute = attributesMappingEntry.getKey()
                            localAttribute = attributesMappingEntry.getValue()
                            localAttributeValue = self.getUserValueFromAuth(remoteAttribute, requestParameters)
                            if ((localAttribute != None) & (localAttributeValue != "undefined") & (
                                        localAttribute != "provider")):
                                try:
                                    value = foundUser.getAttributeValues(str(localAttribute))[0]

                                    if value != localAttributeValue:
                                        userService.setCustomAttribute(foundUser,localAttribute,localAttributeValue)
                                        userService.updateUser(foundUser)

                                except Exception as err:
                                    print("Error in update Attribute " + str(err))

                        userAuthenticated = authenticationService.authenticate(foundUserName)
                        print("Passport-social: Is user authenticated = " + str(userAuthenticated))
                        return True
            
                except Exception as err:
                    print ("Passport-social: Error occurred during request parameter fetching " + str(err))
                    
        if step == 2:
            facesMessages = CdiUtil.bean(FacesMessages)
            facesMessages.setKeepMessages()
            print ("Step 2: Authenticate() executed successfully")
            print("self.authenticationSteps ---  :",self.authenticationSteps)
            if(self.isMFAEnabled=="true"):
                print ("Step 2: Authenticate() MFA enabled for user")
                print ("sessionId is: " + str(sessionId))
                print ("session_attributes is: " + str(session_attributes))
                print ("requestParameters is:" + str(requestParameters))
                # print ("faceMessage is: " + str(facesMessages))
                isEmailMFAComplete = self.initiateEmailMFA(sessionId,session_attributes,requestParameters)

                if isEmailMFAComplete :
                    self.isUserAuthenticated = True
                    return isEmailMFAComplete
                else :
                    return False
                
        else:
            return False

    def loadEmailMFAConfigs(self,sessionId,session_attributes):
        # Generate Random six digit code and store it in array
        code = random.randint(100000, 999999)

         # Get current timestamp
        current_timestamp = int(time.time())

        # Store code and timestamp in session attributes
        session_attributes.put("emailcode", code)
        session_attributes.put("emailcode_timestamp", current_timestamp)
        print("EMAIL OTP INITIATE TIMESTAMP %s" % current_timestamp)

        # Get code and save it in LDAP temporarily with special session entry
        self.identity.setWorkingParameter("emailcode", code)
        
        # fetch from persistence
        sessionId.getSessionAttributes().put("emailcode", code)


        # Set your SendGrid API key
        sendgrid_api_key = self.SendGrid_API_KEY

        #Email configuration
        from_email = self.SMTP_FROM_USER
        to_email = self.user_email
        subject = 'OTP for Authentication'

        # Read the HTML template from the file
        print("before opening the file")

        with open(
            "/opt/gluu/jetty/oxauth/custom/pages/email_otp_template.html", "r"
        ) as template_file:
            html_template = template_file.read()
        
        print("file opened",html_template)

        # Replace placeholders with dynamic values
        html_template = html_template.replace(
            '%OTP%', str(session_attributes.get("emailcode"))
        )
        print("after setting otp",html_template)
        print("user full name is",self.userfullname)
        html_template = html_template.replace('%Name%', self.userfullname)
        print("after setting user fullname",html_template)
        
        sg = SendGrid(sendgrid_api_key)
        content = Content("text/html", html_template)
        mail = Mail(from_email, subject, to_email, content)

        request = Request()
        
        try:
            request.setMethod(Method.POST)
            request.setEndpoint("mail/send")
            request.setBody(mail.build())
            response = sg.api(request)

            status_code = response.getStatusCode()

            print("Status Code:", status_code)

            print("SendGrid Response Body ", response.getBody())
            print("SendGrid Response Headers " , response.getHeaders())

            if 200 <= status_code < 300:
                print("Email Sent Successfully to User %s :"%to_email)
            else: 
                print("Failed to send email.")
                facesMessages = CdiUtil.bean(FacesMessages)
                facesMessages.setKeepMessages()
                facesMessages.add(FacesMessage.SEVERITY_ERROR, "Failed to send email")

            session_attributes.put("otpTimeLeft", "60")

        except Exception as e:
            print("An error occurred:", e)
        
    
    def initiateEmailMFA(self,sessionId,session_attributes,requestParameters):
        self.calculateOtpTimeRemaining(session_attributes)
        

        if self.isMFAEnabled == "true":
            print("MFA enabled ")
            resendOTP = ServerUtil.getFirstValue(requestParameters, "OtpEmailloginForm:resendOtp")
            facesMessages = CdiUtil.bean(FacesMessages)
            facesMessages.setKeepMessages()
            otpTimeLeft = int(session_attributes.get("otpTimeLeft"))
            print("Resend OTP Status  ", resendOTP)

            if resendOTP == "true" and self.isUserAuthenticated == False and otpTimeLeft<=0:
                if self.maxResendOTPAttempts <= 3:
                    self.loadEmailMFAConfigs(sessionId, session_attributes)
                    print("Email ReSent ")
                    self.maxResendOTPAttempts += 1
                    facesMessages.add(FacesMessage.SEVERITY_ERROR, "Email Resent.")
                    return False
                else: 
                    facesMessages.add(FacesMessage.SEVERITY_ERROR, "You have exceeded max resend OTP attempts.Please click on Back to Login")
                    return False

        print ("==Email OTP STEP 2==")
        emailpasscode = ServerUtil.getFirstValue(requestParameters, "emailpasscode")
        print("Email OTP Form Passcode is :%s"%emailpasscode)
        code = session_attributes.get("emailcode")
        print ('=======> Session code is "%s"' % str(code))

        # Fetch timestamp from session attributes
        timestamp = session_attributes.get("emailcode_timestamp")
        current_timestamp = int(time.time())

        # Define the OTP expiration time (in seconds)
        otp_expiration_time = 60  # Adjust as needed

        # Calculate the time difference
        time_difference = current_timestamp - timestamp
        
        # Check if the OTP has expired
        if time_difference > otp_expiration_time:
            # resend otp logic        
            print("Email OTP. The OTP has expired.")
            facesMessages = CdiUtil.bean(FacesMessages)
            facesMessages.setKeepMessages()
            facesMessages.add(FacesMessage.SEVERITY_ERROR, "The OTP has expired. Please request a new OTP.")
            return False

        # fetch from persistence
        code = sessionId.getSessionAttributes().get("emailcode")
        print ('=======> Database code is "%s"' % str(code))
        self.identity.setSessionId(sessionId)
        print ("Email OTP. Code: %s" % str(code))
    
        if code is None:
            print ("Email OTP. Failed to find previously sent code")
            return False

        if emailpasscode is None:
            print ("Email OTP. Passcode is empty")
            facesMessages = CdiUtil.bean(FacesMessages)
            facesMessages.setKeepMessages()
            facesMessages.add(FacesMessage.SEVERITY_ERROR, "Incorrect Email OTP code, please try again.")
            return False

        if len(emailpasscode) != 6:
            print ("Email OTP. Passcode from response is not 6 digits: %s" % emailpasscode)
            facesMessages = CdiUtil.bean(FacesMessages)
            facesMessages.setKeepMessages()
            facesMessages.add(FacesMessage.SEVERITY_ERROR, "Please Enter 6 digits valid OTP.")
            return False

        if str(emailpasscode) == str(code):
            print ("Email OTP, SUCCESS! User entered the same code!")
            print ("===Email OTP SECOND STEP DONE PROPERLY")
            return True

        print ("Email OTP. FAIL! User entered the wrong code! %s != %s" % (emailpasscode, code))
        facesMessages = CdiUtil.bean(FacesMessages)
        facesMessages.setKeepMessages()
        facesMessages.add(FacesMessage.SEVERITY_ERROR, "Incorrect Email OTP code, please try again.")
        print ("===Email OTP SECOND STEP FAILED: INCORRECT CODE")
        return False

    def prepareForStep(self, configurationAttributes, requestParameters, step):
        extensionResult = self.extensionPrepareForStep(configurationAttributes, requestParameters, step)
        if extensionResult != None:
            return extensionResult
        
        print("self.authenticationSteps ----  :",self.authenticationSteps)

        if (step == 1):
            print ("Passport-social: Prepare for Step 1 method call")
            identity = CdiUtil.bean(Identity)
            sessionId =  identity.getSessionId()
            sessionAttribute = sessionId.getSessionAttributes()
            print ("Passport-social: session %s" % sessionAttribute)
            oldState = sessionAttribute.get("state")

            if(oldState == None):
                print ("Passport-social: old state is none")
                return True
            else:
                print ("Passport-social: state is obtained")
                try:
                    stateBytes = Base64Util.base64urldecode(oldState)
                    state = StringUtil.fromBytes(stateBytes)
                    stateObj = json.loads(state)    
                    print (stateObj["provider"])
                    for y in stateObj:
                        print (y,':',stateObj[y])
                    httpService = CdiUtil.bean(HttpService)
                    facesService = CdiUtil.bean(FacesService)
                    facesContext = CdiUtil.bean(FacesContext)
                    httpclient = httpService.getHttpsClient()
                    headersMap = HashMap()
                    headersMap.put("Accept", "text/json")
                    host = facesContext.getExternalContext().getRequest().getServerName()
                    url = "https://"+host+"/passport/token"
                    print ("Passport-social: url %s" %url)
                    resultResponse = httpService.executeGet(httpclient, url , headersMap)
                    http_response = resultResponse.getHttpResponse()
                    response_bytes = httpService.getResponseContent(http_response)
                    szResponse = httpService.convertEntityToString(response_bytes)
                    print ("Passport-social: szResponse %s" % szResponse)
                    tokenObj = json.loads(szResponse)
                    print ("Passport-social: /passport/auth/saml/"+stateObj["provider"]+"/"+tokenObj["token_"])
                    facesService.redirectToExternalURL("/passport/auth/saml/"+stateObj["provider"]+"/"+tokenObj["token_"])

                except Exception as err:
                            print (str(err))
                            return True
            return True
        elif (step == 2):
                print("self.authenticationSteps -----  :",self.authenticationSteps)
                print ("Email OTP. Prepare for Step 2")
                return True
        else:
            return True
            
    def getExtraParametersForStep(self, configurationAttributes, step):
        identity = CdiUtil.bean(Identity)
        sessionId =  identity.getSessionId()
        sessionAttribute = sessionId.getSessionAttributes()
        print("self.authenticationSteps ------  :",self.authenticationSteps)

        if step == 2:
            if(self.isMFAEnabled=="true"):
                print("self.authenticationSteps -------  :",self.authenticationSteps)
                print("get extra parameter for step 2 - email MFA")
                print("Arrays.asList(emailpasscode)",Arrays.asList("emailpasscode"))
                self.calculateOtpTimeRemaining(sessionAttribute)
                return Arrays.asList("emailpasscode")
        print("returning None for getExtraParametersForStep")
        return None
    
    def calculateOtpTimeRemaining(self,session_attributes):

        # Fetch timestamp from session attributes
        timestamp = session_attributes.get("emailcode_timestamp")
        current_timestamp = int(time.time())

        # Define the OTP expiration time (in seconds)
        otp_expiration_time = 60  # Adjust as needed

        # Calculate the time difference
        time_difference = current_timestamp - timestamp
        timeLeft = otp_expiration_time - time_difference
        session_attributes.put("otpTimeLeft",timeLeft)

        if(timeLeft < 0 ):
            session_attributes.put("otpTimeLeft","0") 

    def getCountAuthenticationSteps(self, configurationAttributes):
        print("self.authenticationSteps -------  :",self.authenticationSteps)
        return self.authenticationSteps
       
    def getPageForStep(self, configurationAttributes, step):
        extensionResult = self.extensionGetPageForStep(configurationAttributes, step)
        if extensionResult != None:
            return extensionResult
        
        request = FacesContext.getCurrentInstance().getExternalContext().getRequest()
        print("self.authenticationSteps --------  :",self.authenticationSteps)

        if(step ==1):
            self.authenticationSteps = 1
            self.maxResendOTPAttempts= 1
            self.isUserAuthenticated = False

        if request.getParameter('redirect_uri'):
             self.client_host_uri = request.getParameter('redirect_uri')
             print("client redirect_uri is  %s"%self.client_host_uri)
             parsed_uri = urlparse(self.client_host_uri)
             self.client_host_uri = parsed_uri.scheme + "://" + parsed_uri.netloc
             print("Client redirect_uri hostname is %s" % self.client_host_uri)

        if (step == 1):
            print ("step 1 for getPageForStep executed")
            return "/auth/passport/passportlogin.xhtml"
        elif (step == 2):
            print ("step 2 for getPageForStep executed")
            return "/auth/passport/email_otp.xhtml"
        
        return "/auth/passport/passportpostlogin.xhtml"

    def logout(self, configurationAttributes, requestParameters):
        return True
    
    def setMessageError(self, severity, msg):
        facesMessages = CdiUtil.bean(FacesMessages)
        facesMessages.setKeepMessages()
        facesMessages.clear()
        facesMessages.add(severity, msg)

    def prepareAttributesMapping(self, remoteAttributesList, localAttributesList):
        try:
            remoteAttributesListArray = StringHelper.split(remoteAttributesList, ",")
            if (ArrayHelper.isEmpty(remoteAttributesListArray)):
                print("Passport-social: PrepareAttributesMapping. There is no attributes specified in remoteAttributesList property")
                return None

            localAttributesListArray = StringHelper.split(localAttributesList, ",")
            if (ArrayHelper.isEmpty(localAttributesListArray)):
                print("Passport-social: PrepareAttributesMapping. There is no attributes specified in localAttributesList property")
                return None

            if (len(remoteAttributesListArray) != len(localAttributesListArray)):
                print("Passport-social: PrepareAttributesMapping. The number of attributes in remoteAttributesList and localAttributesList isn't equal")
                return None

            attributeMapping = IdentityHashMap()
            containsUid = False
            i = 0
            count = len(remoteAttributesListArray)
            while (i < count):
                remoteAttribute = StringHelper.toLowerCase(remoteAttributesListArray[i])
                localAttribute = StringHelper.toLowerCase(localAttributesListArray[i])
                attributeMapping.put(remoteAttribute, localAttribute)
                if (StringHelper.equalsIgnoreCase(localAttribute, "uid")):
                    containsUid = True

                i = i + 1

            if (not containsUid):
                print ("Passport-social: PrepareAttributesMapping. There is no mapping to mandatory 'uid' attribute")
                return None

            return attributeMapping
        except Exception as err:
            print("Passport-social: Exception inside prepareAttributesMapping " + str(err))

    def getUidRemoteAttr(self):
        try:
            for attributesMappingEntry in self.attributesMapping.entrySet():
                remoteAttribute = attributesMappingEntry.getKey()
                localAttribute = attributesMappingEntry.getValue()
                if localAttribute == "uid":
                    return remoteAttribute
            else:
                return "Not Get UID related remote attribute"
        except Exception as err:
            print("Passport-social: Exception inside getUidRemoteAttr " + str(err))

    def extensionAuthenticate(self, configurationAttributes, requestParameters, step):
        if (self.extensionModule == None):
            return None

        try:
            result = self.extensionModule.authenticate(configurationAttributes, requestParameters, step)
            print ("Passport-social: Extension. Authenticate: '%s'" % result)
            return result
        except Exception as ex:
            print ("Passport-social: Extension. Authenticate. Failed to execute postLogin method")
            print ("Passport-social: Extension. Authenticate. Unexpected error:", ex)
        except java.lang.Throwable as ex:
            print ("Passport-social: Extension. Authenticate. Failed to execute postLogin method")
            ex.printStackTrace() 
                    
        return True

    def extensionGetPageForStep(self, configurationAttributes, step):
        if (self.extensionModule == None):
            return None

        try:
            result = self.extensionModule.getPageForStep(configurationAttributes, step)
            print ("Passport-social: Extension. Get page for Step: '%s'" % result)
            return result
        except Exception as ex:
            print ("Passport-social: Extension. Get page for Step. Failed to execute postLogin method")
            print ("Passport-social: Extension. Get page for Step. Unexpected error:", ex)
        except java.lang.Throwable as ex:
            print ("Passport-social: Extension. Get page for Step. Failed to execute postLogin method")
            ex.printStackTrace() 

        return None

    def extensionPrepareForStep(self, configurationAttributes, requestParameters, step):
        if (self.extensionModule == None):
            return None

        try:
            result = self.extensionModule.prepareForStep(configurationAttributes, requestParameters, step)
            print ("Passport-social: Extension. Prepare for Step: '%s'" % result)
            return result
        except Exception as ex:
            print ("Passport-social: Extension. Prepare for Step. Failed to execute postLogin method")
            print ("Passport-social: Extension. Prepare for Step. Unexpected error:", ex)
        except java.lang.Throwable as ex:
            print ("Passport-social: Extension. Prepare for Step. Failed to execute postLogin method")
            ex.printStackTrace() 

        return None