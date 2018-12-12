namespace Microsoft.Graph.Auth
{
    using Microsoft.Identity.Client;
    public interface ITokenCacheStorage
    {
        TokenCache GetTokenCacheInstance();
    }
}
