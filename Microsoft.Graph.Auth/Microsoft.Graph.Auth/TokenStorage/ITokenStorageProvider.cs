// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using System.Threading.Tasks;
    public interface ITokenStorageProvider
    {
        Task SetTokenCacheAsync(string cacheId, byte[] tokenCache);
        Task<byte[]> GetTokenCacheAsync(string cacheId);
    }
}
