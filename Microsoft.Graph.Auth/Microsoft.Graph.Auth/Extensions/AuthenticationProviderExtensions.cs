using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Microsoft.Graph.Auth
{
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
    }
}
