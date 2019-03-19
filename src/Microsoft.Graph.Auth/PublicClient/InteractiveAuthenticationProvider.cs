// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using System;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Threading.Tasks;
    using Microsoft.Graph.Auth.Helpers;
    using Microsoft.Identity.Client;

    /// <summary>
    /// An <see cref="IAuthenticationProvider"/> implementation using MSAL.Net to acquire token interactively
    /// </summary>
    public partial class InteractiveAuthenticationProvider : MsalAuthenticationBase, IAuthenticationProvider
    {
        /// <summary>
        /// A UIBehavior property
        /// </summary>
        public UIBehavior UIBehavior { get; set; }

        /// <summary>
        /// A UIParent property
        /// </summary>
        public UIParent UIParent { get; set; }

        /// <summary>
        /// Constructs a new <see cref="InteractiveAuthenticationProvider"/>
        /// </summary>
        /// <param name="publicClientApplication">A <see cref="IPublicClientApplication"/> to pass to <see cref="DeviceCodeProvider"/> for authentication.</param>
        /// <param name="scopes">Scopes required to access Microsoft Graph. This defaults to https://graph.microsoft.com/.default when none is set.</param>
        /// <param name="uiBehavior">Designed interactive experience for the user. Defaults to <see cref="UIBehavior.SelectAccount"/>.</param>
        /// <param name="uiParent">Object containing a reference to the parent window/activity. REQUIRED for Xamarin.Android only.</param>
        public InteractiveAuthenticationProvider(
            IPublicClientApplication publicClientApplication,
            string[] scopes = null,
            UIBehavior? uiBehavior = null,
            UIParent uiParent = null)
            : base(scopes)
        {
            ClientApplication = publicClientApplication ?? throw new AuthenticationException(
                    new Error
                    {
                        Code = ErrorConstants.Codes.InvalidRequest,
                        Message = string.Format(ErrorConstants.Message.NullValue, "publicClientApplication")
                    });
            UIBehavior = uiBehavior ?? UIBehavior.SelectAccount;
            UIParent = uiParent;
        }

        /// <summary>
        /// Creates a new <see cref="IPublicClientApplication"/>
        /// </summary>
        /// <param name="clientId">Client ID (also known as <i>Application ID</i>) of the application as registered in the application registration portal (https://aka.ms/msal-net-register-app).</param>
        /// <param name="tokenStorageProvider">A <see cref="ITokenStorageProvider"/> for storing and retrieving access token.</param>
        /// <param name="tenant">Tenant to sign-in users. This defaults to <c>common</c> if non is specified.</param>
        /// <param name="nationalCloud">A <see cref="NationalCloud"/> which identifies the national cloud endpoint to use as the authority. This defaults to the global cloud <see cref="NationalCloud.Global"/> (https://login.microsoftonline.com).</param>
        /// <returns>A <see cref="IPublicClientApplication"/></returns>
        public static IPublicClientApplication CreateClientApplication(string clientId,
            ITokenStorageProvider tokenStorageProvider = null,
            string tenant = null,
            NationalCloud nationalCloud = NationalCloud.Global)
        {
            TokenCacheProvider tokenCacheProvider = new TokenCacheProvider(tokenStorageProvider);
            string authority = NationalCloudHelpers.GetAuthority(nationalCloud, tenant ?? AuthConstants.Tenants.Common);
            return new PublicClientApplication(clientId, authority, tokenCacheProvider.GetTokenCacheInstnce());
        }

        /// <summary>
        /// Adds an authentication header to the incoming request by checking the application's <see cref="TokenCache"/>
        /// for an unexpired access token. If a token is not found or expired, it gets a new one.
        /// </summary>
        /// <param name="httpRequestMessage">A <see cref="HttpRequestMessage"/> to authenticate.</param>
        public async Task AuthenticateRequestAsync(HttpRequestMessage httpRequestMessage)
        {
            GraphRequestContext requestContext = httpRequestMessage.GetRequestContext();
            MsalAuthenticationProviderOption msalAuthProviderOption = httpRequestMessage.GetMsalAuthProviderOption();
            IAccount account = new GraphAccount(msalAuthProviderOption.UserAccount);
            AuthenticationResult authenticationResult = await this.GetAccessTokenSilentAsync(msalAuthProviderOption);

            if (authenticationResult == null)
            {
                authenticationResult = await GetNewAccessTokenAsync(account, msalAuthProviderOption.Scopes ?? Scopes);
            }

            if (!string.IsNullOrEmpty(authenticationResult.AccessToken))
                httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue(CoreConstants.Headers.Bearer, authenticationResult.AccessToken);
        }

        private async Task<AuthenticationResult> GetNewAccessTokenAsync(IAccount account, string[] scopes)
        {
            IPublicClientApplication publicClientApplication = (ClientApplication as IPublicClientApplication);
            AuthenticationResult authenticationResult = null;
            
            int retryCount = 0;
            string extraQueryParameter = null;
            do
            {
                try
                {
                    authenticationResult = await publicClientApplication.AcquireTokenAsync(scopes, account, UIBehavior, extraQueryParameter, null, ClientApplication.Authority, UIParent);
                    break;
                }
                catch (MsalServiceException serviceException)
                {
                    if (serviceException.ErrorCode == ErrorConstants.Codes.TemporarilyUnavailable)
                    {
                        TimeSpan delay = this.GetRetryAfter(serviceException);
                        retryCount++;
                        // pause execution
                        await Task.Delay(delay);
                    }
                    else if (serviceException.Claims != null)
                    {
                        extraQueryParameter = $"claims={serviceException.Claims}";
                        retryCount++;
                    }
                    else
                    {
                        throw new AuthenticationException(
                            new Error
                            {
                                Code = ErrorConstants.Codes.GeneralException,
                                Message = ErrorConstants.Message.UnexpectedMsalException
                            },
                            serviceException);
                    }
                }
                catch (Exception exception)
                {
                    throw new AuthenticationException(
                            new Error
                            {
                                Code = ErrorConstants.Codes.GeneralException,
                                Message = ErrorConstants.Message.UnexpectedException
                            },
                            exception);
                }

            } while (retryCount < MaxRetry);


            return authenticationResult;
        }
    }
}
