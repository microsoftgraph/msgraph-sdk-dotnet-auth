using Microsoft.Identity.Client;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Graph.Auth
{
    public abstract class MsalAuthenticationBase
    {
        public ClientApplicationBase ClientApplication { get;}
        public string[] Scopes { get; }

        public MsalAuthenticationBase(ClientApplicationBase clientApplication, string[] scopes)
        {
            ClientApplication = clientApplication;
            Scopes = scopes;
        }

        private async Task<string> GetAccessTokenSilentAsync()
        {
            string accessToken = null;
            IEnumerable<IAccount> users = await ClientApplication.GetAccountsAsync();
            if (users.Any())
            {
                try
                {
                    AuthenticationResult authResult = await ClientApplication.AcquireTokenSilentAsync(Scopes, users.FirstOrDefault());
                    accessToken = authResult.AccessToken;
                }
                catch (Exception)
                {
                    // TODO: Handle specific MSAL authentication
                }
            }
            return accessToken;
        }

        private async Task<string> GetAccessTokenAsync()
        {
            string accessToken = await GetAccessTokenSilentAsync();
            if (accessToken == null)
            {
                accessToken = await GetNewAccessTokenAsync();
            }

            return accessToken;
        }

        internal async Task AddTokenToRequestAsync(HttpRequestMessage requestMessage)
        {
            string accessToken = await GetAccessTokenAsync();
            requestMessage.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("bearer", accessToken);
        }

        internal abstract Task<string> GetNewAccessTokenAsync();
    }
}
