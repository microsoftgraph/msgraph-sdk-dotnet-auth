using Microsoft.Identity.Client;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Graph.Auth.Test.Mocks
{
    public static class MockAuthResult
    {
        public static AuthenticationResult GetAuthenticationResult(IAccount account = null, string[] scopes = null)
        {
            return new AuthenticationResult(
                accessToken: "access-token" + Convert.ToBase64String(Guid.NewGuid().ToByteArray()),
                isExtendedLifeTimeToken: false,
                uniqueId: "unique-id"+ Guid.NewGuid(),
                expiresOn: DateTimeOffset.Now,
                extendedExpiresOn: DateTimeOffset.Now,
                tenantId: "tenant-id" + Guid.NewGuid(),
                account: account,
                idToken: "id-token" + Convert.ToBase64String(Guid.NewGuid().ToByteArray()),
                scopes: scopes);
        }
    }
}
