// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using Microsoft.Identity.Client;
    using System.Security;

    /// <summary>
    /// Extension methods for the <see cref="IBaseRequest"/> interface.
    /// </summary>
    public static class BaseRequestExtensions
    {
        /// <summary>
        /// Sets Microsoft Graph's scopes that will be used by <see cref="IAuthenticationProvider"/> to authenticate this request
        /// and can be used to perform incremental scope consent.
        /// This only works with the default authentication handler and default set of Microsoft graph authentication providers.
        /// If you use a custom authentication handler or authentication provider, you have to handle it's retrieval in your implementation.
        /// </summary>
        /// <param name="baseRequest">The <see cref="IBaseRequest"/>.</param>
        /// <param name="scopes">Microsoft graph scopes used to authenticate this request.</param>
        public static T WithScopes<T>(this T baseRequest, string[] scopes) where T : IBaseRequest
        {
            string authHandlerOptionKey = typeof(AuthenticationHandlerOption).ToString();
            AuthenticationHandlerOption authHandlerOptions = baseRequest.MiddlewareOptions[authHandlerOptionKey] as AuthenticationHandlerOption;
            AuthenticationProviderOption msalAuthProviderOption = authHandlerOptions.AuthenticationProviderOption as AuthenticationProviderOption ?? new AuthenticationProviderOption();

            msalAuthProviderOption.Scopes = scopes;

            authHandlerOptions.AuthenticationProviderOption = msalAuthProviderOption;
            baseRequest.MiddlewareOptions[authHandlerOptionKey] = authHandlerOptions;

            return baseRequest;
        }

        /// <summary>
        /// Sets MSAL's force refresh flag to <see cref="IAuthenticationProvider"/> for this request. If set to true, <see cref="IAuthenticationProvider"/> will refresh existing access token in cahce.
        /// This defaults to false if not set.
        /// </summary>
        /// <param name="baseRequest">The <see cref="IBaseRequest"/>.</param>
        /// <param name="forceRefresh">A <see cref="bool"/> flag to determine whether refresh access token or not.</param>
        public static T WithForceRefresh<T>(this T baseRequest, bool forceRefresh) where T : IBaseRequest
        {
            string authHandlerOptionKey = typeof(AuthenticationHandlerOption).ToString();
            AuthenticationHandlerOption authHandlerOptions = baseRequest.MiddlewareOptions[authHandlerOptionKey] as AuthenticationHandlerOption;
            AuthenticationProviderOption msalAuthProviderOption = authHandlerOptions.AuthenticationProviderOption as AuthenticationProviderOption ?? new AuthenticationProviderOption();

            msalAuthProviderOption.ForceRefresh = forceRefresh;

            authHandlerOptions.AuthenticationProviderOption = msalAuthProviderOption;
            baseRequest.MiddlewareOptions[authHandlerOptionKey] = authHandlerOptions;

            return baseRequest;
        }

        /// <summary>
        /// Sets <see cref="GraphUserAccount"/> to be used to retrieve an access token for this request.
        /// It is also used to handle multi-user/ multi-tenant access token cache storage and retrieval.
        /// </summary>
        /// <param name="baseRequest">The <see cref="IBaseRequest"/>.</param>
        /// <param name="userAccount">A <see cref="GraphUserAccount"/> that represents a user account. At a minimum, the ObjectId and TenantId must be set.
        /// </param>
        public static T WithUserAccount<T>(this T baseRequest, GraphUserAccount userAccount) where T : IBaseRequest
        {
            string authHandlerOptionKey = typeof(AuthenticationHandlerOption).ToString();
            AuthenticationHandlerOption authHandlerOptions = baseRequest.MiddlewareOptions[authHandlerOptionKey] as AuthenticationHandlerOption;
            AuthenticationProviderOption msalAuthProviderOption = authHandlerOptions.AuthenticationProviderOption as AuthenticationProviderOption ?? new AuthenticationProviderOption();

            msalAuthProviderOption.UserAccount = userAccount;

            authHandlerOptions.AuthenticationProviderOption = msalAuthProviderOption;
            baseRequest.MiddlewareOptions[authHandlerOptionKey] = authHandlerOptions;

            return baseRequest;
        }

        /// <summary>
        /// Sets <see cref="UserAssertion"/> for this request.
        /// This should only be used with <see cref="OnBehalfOfProvider"/>.
        /// </summary>
        /// <param name="baseRequest">The <see cref="IBaseRequest"/>.</param>
        /// <param name="userAssertion">A <see cref="UserAssertion"/> for the user.</param>
        public static T WithUserAssertion<T>(this T baseRequest, UserAssertion userAssertion) where T : IBaseRequest
        {
            string authHandlerOptionKey = typeof(AuthenticationHandlerOption).ToString();
            AuthenticationHandlerOption authHandlerOptions = baseRequest.MiddlewareOptions[authHandlerOptionKey] as AuthenticationHandlerOption;
            AuthenticationProviderOption msalAuthProviderOption = authHandlerOptions.AuthenticationProviderOption as AuthenticationProviderOption ?? new AuthenticationProviderOption();

            msalAuthProviderOption.UserAssertion = userAssertion;

            authHandlerOptions.AuthenticationProviderOption = msalAuthProviderOption;
            baseRequest.MiddlewareOptions[authHandlerOptionKey] = authHandlerOptions;

            return baseRequest;
        }

        /// <summary>
        /// Sets a username (email) and password of an Azure AD account to authenticate.
        /// This should only be used with <see cref="UsernamePasswordProvider"/>.
        /// This provider is NOT RECOMMENDED because it exposes the users password.
        /// We recommend you use <see cref="IntegratedWindowsAuthenticationProvider"/> instead.
        /// </summary>
        /// <param name="baseRequest">The <see cref="IBaseRequest"/>.</param>
        /// <param name="email">Email address of the user to authenticate.</param>
        /// <param name="password">Password of the user to authenticate.</param>
        public static T WithUsernamePassword<T>(this T baseRequest, string email, SecureString password) where T : IBaseRequest
        {
            string authHandlerOptionKey = typeof(AuthenticationHandlerOption).ToString();
            AuthenticationHandlerOption authHandlerOptions = baseRequest.MiddlewareOptions[authHandlerOptionKey] as AuthenticationHandlerOption;
            AuthenticationProviderOption msalAuthProviderOption = authHandlerOptions.AuthenticationProviderOption as AuthenticationProviderOption ?? new AuthenticationProviderOption();

            msalAuthProviderOption.Password = password;
            msalAuthProviderOption.UserAccount = new GraphUserAccount { Email = email };

            authHandlerOptions.AuthenticationProviderOption = msalAuthProviderOption;
            baseRequest.MiddlewareOptions[authHandlerOptionKey] = authHandlerOptions;

            return baseRequest;
        }
    }
}