// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using Microsoft.Graph.Auth.Extensions;
    using Microsoft.Identity.Client;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Threading.Tasks;

    /// <summary>
    /// An <see cref="IAuthenticationProvider"/> implementation using MSAL.Net to acquire token interactively
    /// </summary>
    public partial class InteractiveAuthenticationProvider : IAuthenticationProvider
    {
        /// <summary>
        /// A <see cref="IPublicClientApplication"/> property.
        /// </summary>
        public IPublicClientApplication ClientApplication { get; set; }

        /// <summary>
        /// A scopes property.
        /// </summary>
        internal IEnumerable<string> Scopes { get; set; }

        /// <summary>
        /// Indicates the interactive experience for the user.
        /// </summary>
        public Prompt Prompt { get; set; }

#if NET45
        /// <summary>
        /// Parent activity or window.
        /// </summary>
        public System.Windows.Forms.IWin32Window ParentWindow { get; set; }

        /// <summary>
        /// Parent activity or window.
        /// </summary>
        public IntPtr ParentPointer { get; set; }

        /// <summary>
        /// Constructs a new <see cref="InteractiveAuthenticationProvider"/>
        /// </summary>
        /// <param name="publicClientApplication">A <see cref="IPublicClientApplication"/> to pass to <see cref="InteractiveAuthenticationProvider"/> for authentication.</param>
        /// <param name="scopes">Scopes required to access Microsoft Graph. This defaults to https://graph.microsoft.com/.default when none is set.</param>
        /// <param name="prompt">Designed interactive experience for the user. Defaults to <see cref="Prompt.SelectAccount"/>.</param>
        /// <param name="window">Object containing a reference to the parent window/activity.</param>
        /// <param name="pointer">Object containing a reference to the parent window/activity.</param>
        public InteractiveAuthenticationProvider(
            IPublicClientApplication publicClientApplication,
            IEnumerable<string> scopes = null,
            Prompt? prompt = null,
            System.Windows.Forms.IWin32Window window = null,
            IntPtr pointer = default(IntPtr))
        {
            Scopes = scopes ?? new List<string> { AuthConstants.DefaultScopeUrl };
            if (Scopes.Count() == 0)
            {
                throw new AuthenticationException(
                    new Error { Code = ErrorConstants.Codes.InvalidRequest, Message = ErrorConstants.Message.EmptyScopes },
                    new ArgumentException());
            }

            ClientApplication = publicClientApplication ?? throw new AuthenticationException(
                    new Error
                    {
                        Code = ErrorConstants.Codes.InvalidRequest,
                        Message = string.Format(ErrorConstants.Message.NullValue, nameof(publicClientApplication))
                    });
            Prompt = prompt ?? Prompt.SelectAccount;
            ParentWindow = window;
            ParentPointer = pointer;
        }
#elif NETSTANDARD1_3
        /// <summary>
        /// Parent activity or window.
        /// </summary>
        public object Parent { get; set; }

        /// <summary>
        /// Constructs a new <see cref="InteractiveAuthenticationProvider"/>
        /// </summary>
        /// <param name="publicClientApplication">A <see cref="IPublicClientApplication"/> to pass to <see cref="InteractiveAuthenticationProvider"/> for authentication.</param>
        /// <param name="scopes">Scopes required to access Microsoft Graph. This defaults to https://graph.microsoft.com/.default when none is set.</param>
        /// <param name="prompt">Designed interactive experience for the user. Defaults to <see cref="Prompt.SelectAccount"/>.</param>
        /// <param name="parent">Object containing a reference to the parent window/activity. REQUIRED for Xamarin.Android only.</param>
        public InteractiveAuthenticationProvider(IPublicClientApplication publicClientApplication, IEnumerable<string> scopes = null, Prompt? prompt = null, object parent = null)
        {
            Scopes = scopes ?? new List<string> { AuthConstants.DefaultScopeUrl };
            if (Scopes.Count() == 0)
            {
                throw new AuthenticationException(
                    new Error { Code = ErrorConstants.Codes.InvalidRequest, Message = ErrorConstants.Message.EmptyScopes },
                    new ArgumentException());
            }

            ClientApplication = publicClientApplication ?? throw new AuthenticationException(
                    new Error
                    {
                        Code = ErrorConstants.Codes.InvalidRequest,
                        Message = string.Format(ErrorConstants.Message.NullValue, nameof(publicClientApplication))
                    });
            Prompt = prompt ?? Prompt.SelectAccount;
            Parent = parent;
        }
#endif

        /// <summary>
        /// Adds an authentication header to the incoming request by checking the application's <see cref="TokenCache"/>
        /// for an unexpired access token. If a token is not found or expired, it gets a new one.
        /// </summary>
        /// <param name="httpRequestMessage">A <see cref="HttpRequestMessage"/> to authenticate.</param>
        public async Task AuthenticateRequestAsync(HttpRequestMessage httpRequestMessage)
        {
            AuthenticationProviderOption msalAuthProviderOption = httpRequestMessage.GetMsalAuthProviderOption();
            msalAuthProviderOption.Scopes = msalAuthProviderOption.Scopes ?? Scopes.ToArray();

            IAccount account = new GraphAccount(msalAuthProviderOption.UserAccount);
            AuthenticationResult authenticationResult = await ClientApplication.GetAccessTokenSilentAsync(msalAuthProviderOption);

            if (authenticationResult == null)
            {
                authenticationResult = await GetNewAccessTokenAsync(account, msalAuthProviderOption);
            }

            if (!string.IsNullOrEmpty(authenticationResult.AccessToken))
                httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue(CoreConstants.Headers.Bearer, authenticationResult.AccessToken);
        }

        private async Task<AuthenticationResult> GetNewAccessTokenAsync(IAccount account, AuthenticationProviderOption msalAuthProviderOption)
        {
            AuthenticationResult authenticationResult = null;
            
            int retryCount = 0;
            string extraQueryParameter = null;
            do
            {
                try
                {
                    var builder = ClientApplication.AcquireTokenInteractive(msalAuthProviderOption.Scopes)
                        .WithAccount(account)
                        .WithPrompt(Prompt)
                        .WithExtraQueryParameters(extraQueryParameter)
                        .WithExtraScopesToConsent(null)
                        .WithAuthority(ClientApplication.Authority);
#if NET45
                    if (ParentWindow != null)
                    {
                        builder = builder.WithParentActivityOrWindow(ParentWindow);
                    }
                    else
                    {
                        builder = builder.WithParentActivityOrWindow(ParentPointer);
                    }
#elif NETSTANDARD1_3
                    builder = builder.WithParentActivityOrWindow(Parent);
#endif
                    authenticationResult = await builder.ExecuteAsync();
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

            } while (retryCount < msalAuthProviderOption.MaxRetry);


            return authenticationResult;
        }
    }
}
