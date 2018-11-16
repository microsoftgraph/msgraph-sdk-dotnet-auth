using Microsoft.Identity.Client;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Graph.Auth.Helpers
{
    public static class Oauth2Helper
    {
        public static async Task<Uri> GenerateAuthorizationRequestUrl(ConfidentialClientApplication cca, string[] scopes)
        {
            Uri autorizationUrl = await cca.GetAuthorizationRequestUrlAsync(scopes, String.Empty, null);
            return autorizationUrl;
        }
    }
}
