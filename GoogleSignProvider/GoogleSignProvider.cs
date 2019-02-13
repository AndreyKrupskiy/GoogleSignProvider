

namespace Sitecore.Social.GooglePlus.Networks.Providers
{
    using DotNetOpenAuth.OAuth2;
    using Google.Apis.Authentication.OAuth2;
    using Google.Apis.Authentication.OAuth2.DotNetOpenAuth;
    using Ninject;
    using Ninject.Parameters;
    using Google.Apis.Auth.OAuth2;
    using Google.Apis.PeopleService.v1;
    using Google.Apis.PeopleService.v1.Data;
    using Google.Apis.Services;
    using Sitecore.Diagnostics;
    using Sitecore.Social.GooglePlus.Connector.Paths;
    using Sitecore.Social.GooglePlus.Exceptions.Analyzers;
    using Sitecore.Social.Infrastructure;
    using Sitecore.Social.Infrastructure.Logging;
    using Sitecore.Social.Infrastructure.Utils;
    using Sitecore.Social.NetworkProviders;
    using Sitecore.Social.NetworkProviders.Args;
    using Sitecore.Social.NetworkProviders.Interfaces;
    using Sitecore.Social.NetworkProviders.NetworkFields;
    using Sitecore.Web;
    using System;
    using System.Collections;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Reflection;
    using System.Runtime.CompilerServices;
    using System.Web;
    using System.Web.Script.Serialization;

    public class GooglePlusProvider : NetworkProvider, IAuth, IGetAccountInfo, IAccessTokenSecretRenewal
    {
        private readonly NativeApplicationClient _provider;
        private IAuthorizationState _auth;
        private IAuthorizationState auth;

        public GooglePlusProvider(Sitecore.Social.NetworkProviders.Application application) : base(application)
        {
            this._provider = new NativeApplicationClient(GoogleAuthenticationServer.Description);
        }

        public void AuthGetAccessToken(AuthArgs args)
        {
            HttpRequest request = HttpContext.Current.Request;
            if (!string.IsNullOrEmpty(request.QueryString.Get("error")))
            {
                return;
            }
            else
            {
                string str = request.QueryString.Get("code");
                if (string.IsNullOrEmpty(str))
                {
                    return;
                }
                else
                {
                    this._provider.ClientIdentifier = (args.Application.ApplicationKey);
                    this._provider.ClientSecret = (args.Application.ApplicationSecret);
                    List<string> list1 = GetScopes();
                    AuthorizationState state1 = new AuthorizationState(list1);
                    state1.Callback =
                        (new Uri(WebUtil.GetFullUrl("/layouts/Social/Connector/SocialLogin.ashx?type=access")));
                    AuthorizationState state = state1;
                    try
                    {
                        this._auth = this._provider.ProcessUserAuthorization(str, state);
                    }
                    catch (WebException exception)
                    {
                        using (WebResponse response = exception.Response)
                        {
                            using (Stream stream = response.GetResponseStream())
                            {
                                if (stream != null)
                                {
                                    string message = new StreamReader(stream).ReadToEnd();
                                    ExecutingContext.Current.IoC.Get<ILogManager>(new IParameter[0]).LogMessage(message,
                                        Sitecore.Social.Infrastructure.Logging.LogLevel.Error, this, exception);
                                }
                            }
                        }
                    }
                }
            }

            if (!string.IsNullOrEmpty(args.CallbackType))
            {
                AuthCompletedArgs args1 = new AuthCompletedArgs();
                args1.Application = args.Application;
                args1.AccessTokenSecret = this._auth.AccessToken;
                args1.RefreshToken = this._auth.RefreshToken;
                args1.AccessTokenSecretExpirationDate = this._auth.AccessTokenExpirationUtc;
                args1.AccessTokenSecretIssueDate = this._auth.AccessTokenIssueDateUtc;
                args1.CallbackPage = args.CallbackUrl;
                args1.ExternalData = args.ExternalData;
                args1.AttachAccountToLoggedInUser = args.AttachAccountToLoggedInUser;
                args1.IsAsyncProfileUpdate = args.IsAsyncProfileUpdate;
                AuthCompletedArgs authCompletedArgs = args1;
                base.InvokeAuthCompleted(args.CallbackType, authCompletedArgs);
            }
        }

        public void AuthGetCode(AuthArgs args)
        {
            this._provider.ClientIdentifier = (args.Application.ApplicationKey);
            this._provider.ClientSecret = (args.Application.ApplicationSecret);
            List<string> list1 = GetScopes();
            AuthorizationState state1 = new AuthorizationState(list1);
            state1.Callback = (new Uri(WebUtil.GetFullUrl("/layouts/Social/Connector/SocialLogin.ashx?type=access")));
            AuthorizationState state = state1;
            string str = this._provider.RequestUserAuthorization(state).ToString();
            if (args.Permissions != null)
            {
                bool flag;
                bool flag1 = bool.TryParse(args.Permissions["offlineAccess"], out flag);
                if ((args.Permissions.ContainsKey("offlineAccess") && flag1) & flag)
                {
                    str = str + "&access_type=offline&approval_prompt=force";
                }
            }

            RedirectUtil.Redirect(str + "&state=" + args.StateKey);
        }

        public AccountBasicData GetAccountBasicData(Account account)
        {
            Assert.IsNotNull(account, "Account parameter is null");
            Person accountData = this.GetAccountData(account);
            string id = null;
            string str2 = null;
            string displayName = null;
            if (accountData != null)
            {
                id = accountData.Metadata.Sources.FirstOrDefault().Id;
                displayName = accountData.Names.FirstOrDefault().DisplayName;
                str2 = (from emailData in accountData.EmailAddresses
                        where string.Compare(emailData.Type, "account", StringComparison.InvariantCultureIgnoreCase) == 0
                        select emailData.Value).FirstOrDefault<string>();
            }

            AccountBasicData data1 = new AccountBasicData();
            data1.Account = account;
            data1.Id = id;
            data1.Email = str2;
            data1.FullName = displayName;
            return data1;
        }

        private Person GetAccountData(Account account)
        {
            Person person;
            try
            {
                this._provider.ClientIdentifier = (base.Application.ApplicationKey);
                this._provider.ClientSecret = (base.Application.ApplicationSecret);
                this.auth = this.GetAuthState(account.AccessTokenSecret);
                var request = new PeopleServiceService(new BaseClientService.Initializer()
                {
                    HttpClientInitializer = GoogleCredential.FromAccessToken(this.auth.AccessToken),


                }).People.Get("people/me");
                request.RequestMaskIncludeField = "person.names,person.emailAddresses,person.metadata";
                person = request.Execute();
                //person = new PeopleServiceService(new OAuth2Authenticator<NativeApplicationClient>(this._provider, new Func<NativeApplicationClient, IAuthorizationState>(this.GetAuthentication))).People.Get("me").Fetch();
            }
            catch (Exception exception)
            {
                new GooglePlusExceptionAnalyzer().Analyze(exception);
                return null;
            }

            return person;
        }

        public string GetAccountId(Account account)
        {
            Person accountData = this.GetAccountData(account);
            return ((accountData != null) ? accountData.Metadata.Sources.FirstOrDefault().Id : null);
        }

        public IEnumerable<Field> GetAccountInfo(Account account,
            IEnumerable<Sitecore.Social.NetworkProviders.NetworkFields.FieldInfo> acceptedFields)
        {
            Assert.IsNotNull(acceptedFields, "AcceptedFields collection must be filled");
            Person accountData = this.GetAccountData(account);
            if (accountData == null)
            {
                return null;
            }

            List<Field> list = new List<Field>();
            foreach (Sitecore.Social.NetworkProviders.NetworkFields.FieldInfo info in from acceptedField in
                    acceptedFields
                                                                                      where !string.IsNullOrEmpty(acceptedField.OriginalKey)
                                                                                      select acceptedField)
            {
                bool propertyNotFoundInType = false;
                char[] separator = new char[] { '.' };
                object resultedObject = this.GetPropertyValue(accountData, info.OriginalKey.Split(separator),
                    ref propertyNotFoundInType);
                if (propertyNotFoundInType)
                {
                    object[] args = new object[] { info.OriginalKey };
                    ExecutingContext.Current.IoC.Get<ILogManager>(new IParameter[0]).LogMessage(
                        string.Format(CultureInfo.CurrentCulture, "There is no field \"{0}\" in a Person object", args),
                        Sitecore.Social.Infrastructure.Logging.LogLevel.Warn, this);
                    continue;
                }

                if (resultedObject != null)
                {
                    Field item = new Field();
                    item.Name = base.GetFieldSitecoreKey(info);
                    item.Value = this.TransformToDisplayableString(resultedObject);
                    list.Add(item);
                }
            }

            return list;
        }

        private IAuthorizationState GetAuthentication(NativeApplicationClient arg)
        {
            return this.auth;
        }

        private IAuthorizationState GetAuthState(string accessToken)
        {
            List<string> list1 = GetScopes();
            AuthorizationState state1 = new AuthorizationState(list1);
            state1.AccessToken = (accessToken);
            return state1;
        }

        public string GetDisplayName(Account account)
        {
            Person accountData = this.GetAccountData(account);
            return ((accountData != null) ? accountData.Names.FirstOrDefault().DisplayName : null);
        }

        private object GetPropertyValue(object parent, string[] propertyNames, ref bool propertyNotFoundInType)
        {
            if ((propertyNames.Length == 0) || (parent == null))
            {
                return parent;
            }

            string name = propertyNames[0];
            PropertyInfo property = parent.GetType().GetProperty(name);
            if (property == null)
            {
                propertyNotFoundInType = true;
                return null;
            }

            object obj2 = property.GetValue(parent, null);
            return this.GetPropertyValue(obj2, propertyNames.Skip<string>(1).ToArray<string>(),
                ref propertyNotFoundInType);
        }

        public void RefreshAccessTokenSecret(Account account)
        {
            Assert.IsNotNullOrEmpty(account.RefreshToken, "RefreshToken shouldn't be empty");
            AuthorizationState state1 = new AuthorizationState(null);
            state1.RefreshToken = (account.RefreshToken);
            AuthorizationState state = state1;
            this._provider.ClientIdentifier = (account.Application.ApplicationKey);
            this._provider.ClientSecret = (account.Application.ApplicationSecret);
            try
            {
                TimeSpan? nullable = null;
                this._provider.RefreshToken(state, nullable);
                account.AccessTokenSecret = state.AccessToken;
                account.AccessTokenSecretExpirationDate = state.AccessTokenExpirationUtc;
                account.AccessTokenSecretIssueDate = state.AccessTokenIssueDateUtc;
            }
            catch (WebException exception)
            {
                using (WebResponse response = exception.Response)
                {
                    using (Stream stream = response.GetResponseStream())
                    {
                        if (stream != null)
                        {
                            ExecutingContext.Current.IoC.Get<ILogManager>(new IParameter[0]).LogMessage(
                                new StreamReader(stream).ReadToEnd(),
                                Sitecore.Social.Infrastructure.Logging.LogLevel.Error, this, exception);
                        }
                    }
                }
            }
        }

        private string TransformToDisplayableString(object resultedObject)
        {
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            return ((resultedObject is IList) ? serializer.Serialize(resultedObject) : resultedObject.ToString());
        }

        List<string> GetScopes()
        {
            List<string> list1 = new List<string>();
            list1.Add("profile");
            list1.Add("email");
            list1.Add(PeopleServiceService.Scope.UserEmailsRead);
            list1.Add(PeopleServiceService.Scope.UserinfoProfile);
            return list1;
        }
    }
}
