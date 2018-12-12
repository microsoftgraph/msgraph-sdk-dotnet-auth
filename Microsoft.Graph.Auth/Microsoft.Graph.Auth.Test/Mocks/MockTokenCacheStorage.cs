using Microsoft.Graph.Auth.Test.Extensions;
using Microsoft.Identity.Client;
using NSubstitute;
using System;
using System.IO;
using System.Runtime.Serialization.Json;
using System.Text;

namespace Microsoft.Graph.Auth.Test.Mocks
{
    public class MockTokenCacheStorage : ITokenCacheStorage
    {
        private TokenCache cache;
        public MockTokenCacheStorage()
        {
            cache = new TokenCache();
        }
        public TokenCache GetTokenCacheInstance()
        {
            return cache;
        }

        public void BeforeAccessNotification(TokenCacheNotificationArgs args)
        {

        }

        public void AfterAccessNotification(TokenCacheNotificationArgs args)
        {

        }
    }
}