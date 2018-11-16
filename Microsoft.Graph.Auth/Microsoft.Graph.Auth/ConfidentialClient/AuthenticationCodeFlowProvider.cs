using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Identity.Client;

namespace Microsoft.Graph.Auth
{
    public class AuthenticationCodeFlowProvider : MsalAuthenticationBase, IAuthenticationProvider
    {
        public AuthenticationCodeFlowProvider(ConfidentialClientApplication confidentialClientApplication,
            string[] scopes) : base(confidentialClientApplication, scopes)
        {
        }

        public async Task AuthenticateRequestAsync(HttpRequestMessage request)
        {
            await AddTokenToRequestAsync(request);
        }

        internal override async Task<string> GetNewAccessTokenAsync()
        {
            // TODO: perform a challenge - platform specific
            // we can thrown a perform challenge exception back to the user
            throw new MsalAuthException(
                new MsalAuthError
                {
                    Code = MsalAuthErrorCode.AuthChallengeRequired,
                    Message = "Authentication Challange is required"
                });
        }
    }
}
