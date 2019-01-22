// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using Microsoft.Identity.Client;
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Net.Http.Headers;

    internal static class AuthenticationProviderExtensions
    {
        internal static Dictionary<NationalCloud, string> CloudList = new Dictionary<NationalCloud, string>
        {
            { NationalCloud.Global, "https://login.microsoftonline.com/{0}" },
            { NationalCloud.China, "https://login.chinacloudapi.cn/{0}" },
            { NationalCloud.Germany, "https://login.microsoftonline.de/{0}" },
            { NationalCloud.UsGovernment, "https://login.microsoftonline.us/{0}" }
        };

        internal static string GetAuthority(this IAuthenticationProvider authenticationProvider, NationalCloud authorityEndpoint, string tenant)
        {
            string cloudUrl = string.Empty;
            if (!CloudList.TryGetValue(authorityEndpoint, out cloudUrl))
            {
                throw new ArgumentException($" {authorityEndpoint} is an unexpected national cloud type");
            }

            return string.Format(CultureInfo.InvariantCulture, cloudUrl , tenant);
        }

        /// <summary>
        /// Gets <see cref="RetryConditionHeaderValue"/> from <see cref="MsalServiceException"/> and computes when to retry
        /// </summary>
        /// <param name="serviceException">A <see cref="MsalServiceException"/> with RetryAfter header</param>
        /// <returns></returns>

        internal static TimeSpan GetRetryAfter(this IAuthenticationProvider authProvider, MsalServiceException serviceException)
        {
            RetryConditionHeaderValue retryAfter = serviceException.Headers.RetryAfter;
            TimeSpan? delay = null;

            if (retryAfter != null && retryAfter.Delta.HasValue)
            {
                delay = retryAfter.Delta;
            }
            else if (retryAfter != null && retryAfter.Date.HasValue)
            {
                delay = retryAfter.Date.Value.Offset;
            }

            if (delay == null)
                throw new MsalServiceException(serviceException.ErrorCode, MsalAuthErrorConstants.Message.MissingRetryAfterHeader);

            return delay.Value;
        }
    }
}
