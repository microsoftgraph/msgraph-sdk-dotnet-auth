// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using System.Threading.Tasks;
    /// <summary>
    /// Interface for token storage and Retrieval.
    /// </summary>
    public interface ITokenStorageProvider
    {
        /// <summary>
        /// Set's token cache with a provided cacheId key.
        /// </summary>
        /// <param name="cacheId">A unique key used to identify a token cache item.</param>
        /// <param name="tokenCache">The token cache item to store.</param>

        Task SetTokenCacheAsync(string cacheId, byte[] tokenCache);
        /// <summary>
        /// Retrieves a token cache item with the provided cacheId key.
        /// </summary>
        /// <param name="cacheId">A unique key used to identify a token cache item.</param>
        Task<byte[]> GetTokenCacheAsync(string cacheId);
    }
}
