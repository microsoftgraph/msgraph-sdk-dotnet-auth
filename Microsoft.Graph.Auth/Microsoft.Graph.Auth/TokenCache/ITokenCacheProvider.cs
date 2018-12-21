namespace Microsoft.Graph.Auth
{
    using Microsoft.Identity.Client;
    public interface ITokenCacheProvider
    {
        TokenCache GetTokenCacheInstance();
    }
}
