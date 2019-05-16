// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using Microsoft.Identity.Client;
    using System;
    using System.Collections.Generic;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Threading.Tasks;

    /// <summary>
    /// An <see cref="IAuthenticationProvider"/> implementation using MSAL.Net to acquire token interactively
    /// </summary>
    public partial class InteractiveAuthenticationProvider : MsalAuthenticationBase<IPublicClientApplication>, IAuthenticationProvider
    {
        /// <summary>
        /// Indicates the interactive experience for the user.
        /// </summary>
        public Prompt Prompt { get; set; }

        /// <summary>
        /// Parent activity or window.
        /// </summary>
        /// <remarks>
        /// Typically used in Xamarin projects.
        /// </remarks>
        public object Parent { get; set; }

        /// <summary>
        /// Constructs a new <see cref="InteractiveAuthenticationProvider"/>
        /// </summary>
        /// <param name="publicClientApplication">A <see cref="IPublicClientApplication"/> to pass to <see cref="DeviceCodeProvider"/> for authentication.</param>
        /// <param name="scopes">Scopes required to access Microsoft Graph. This defaults to https://graph.microsoft.com/.default when none is set.</param>
        /// <param name="prompt">Designed interactive experience for the user. Defaults to <see cref="Prompt.SelectAccount"/>.</param>
        /// <param name="parent">Object containing a reference to the parent window/activity. REQUIRED for Xamarin.Android only.</param>
        public InteractiveAuthenticationProvider(
            IPublicClientApplication publicClientApplication,
            IEnumerable<string> scopes = null,
            Prompt? prompt = null,
            object parent = null)
            : base(scopes)
        {
            ClientApplication = publicClientApplication ?? throw new AuthenticationException(
                    new Error
                    {
                        Code = ErrorConstants.Codes.InvalidRequest,
                        Message = string.Format(ErrorConstants.Message.NullValue, nameof(publicClientApplication))
                    });
            Prompt = prompt ?? Prompt.SelectAccount;
            Parent = parent;
        }

        /// <summary>
        /// Creates a new <see cref="IPublicClientApplication"/>.
        /// </summary>
        /// <param name="clientId">Client ID (also known as <i>Application ID</i>) of the application as registered in the application registration portal (https://aka.ms/msal-net-register-app).</param>
        /// <param name="tenant">Tenant to sign-in users. This defaults to <see cref="AadAuthorityAudience.AzureAdMultipleOrgs"/> if none is specified.</param>
        /// <param name="redirectUri">The redirect Uri used by the application. This defaults to <i></i> if none is specified.</param>
        /// <param name="cloud">A <see cref="AzureCloudInstance"/> which identifies the cloud endpoint to use as the authority. This defaults to the public cloud <see cref="AzureCloudInstance.AzurePublic"/> (https://login.microsoftonline.com).</param>
        /// <returns>A <see cref="IPublicClientApplication"/></returns>
        /// <exception cref="AuthenticationException"/>
        public static IPublicClientApplication CreateClientApplication(string clientId,
            string tenant = null,
            string redirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient",
            AzureCloudInstance cloud = AzureCloudInstance.AzurePublic)
        {
            if (string.IsNullOrEmpty(clientId))
                throw new AuthenticationException(
                    new Error
                    {
                        Code = ErrorConstants.Codes.InvalidRequest,
                        Message = string.Format(ErrorConstants.Message.NullValue, nameof(clientId))
                    });

            var builder = PublicClientApplicationBuilder
                .Create(clientId)
                .WithRedirectUri(redirectUri);

            if (tenant != null)
                builder = builder.WithAuthority(cloud, tenant);
            else
                builder = builder.WithAuthority(cloud, AadAuthorityAudience.AzureAdMultipleOrgs);

            return builder.Build();
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

        private async Task<AuthenticationResult> GetNewAccessTokenAsync(IAccount account, IEnumerable<string> scopes)
        {
            AuthenticationResult authenticationResult = null;
            
            int retryCount = 0;
            string extraQueryParameter = null;
            do
            {
                try
                {
                    authenticationResult = await ClientApplication.AcquireTokenInteractive(scopes)
                        .WithAccount(account)
                        .WithPrompt(Prompt)
                        .WithExtraQueryParameters(extraQueryParameter)
                        .WithExtraScopesToConsent(null)
                        .WithAuthority(ClientApplication.Authority)
                        .WithParentActivityOrWindow(Parent)
                        .ExecuteAsync();
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
