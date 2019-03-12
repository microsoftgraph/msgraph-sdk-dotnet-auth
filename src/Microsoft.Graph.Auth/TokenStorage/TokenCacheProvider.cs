// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using Microsoft.Identity.Client;

    internal class TokenCacheProvider
    {
        private const string _cacheIdTag = "_msgraph_token";
        private ITokenStorageProvider _tokenStorageProvider = null;
        private TokenCache _tokenCache = new TokenCache();

        internal TokenCacheProvider(ITokenStorageProvider tokenStorageProvider = null)
        {
            _tokenStorageProvider = tokenStorageProvider;
        }

        internal TokenCache GetTokenCacheInstnce()
        {
            if (_tokenStorageProvider != null)
            {
                _tokenCache.SetBeforeAccess(OnBeforeAccess);
                _tokenCache.SetAfterAccess(OnAfterAccess);
            }

            return _tokenCache;
        }

        private async void OnAfterAccess(TokenCacheNotificationArgs args)
        {
            if (args.HasStateChanged)
            {
                await _tokenStorageProvider.SetTokenCacheAsync(args.Account.HomeAccountId.Identifier + _cacheIdTag, _tokenCache.Serialize());
            }
        }

        private async void OnBeforeAccess(TokenCacheNotificationArgs args)
        {
            _tokenCache.Deserialize(await _tokenStorageProvider.GetTokenCacheAsync(args.Account?.HomeAccountId?.Identifier + _cacheIdTag));
        }
    }
}
