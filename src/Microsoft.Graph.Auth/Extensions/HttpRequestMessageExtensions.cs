namespace Microsoft.Graph.Auth
{
    using System.Net.Http;
    internal static class HttpRequestMessageExtensions
    {
        internal static MsalAuthProviderOption GetMsalAuthProviderOption(this HttpRequestMessage httpRequestMessage)
        {
            AuthenticationHandlerOption authHandlerOption = httpRequestMessage.GetMiddlewareOption<AuthenticationHandlerOption>();

            return authHandlerOption?.AuthenticationProviderOption as MsalAuthProviderOption ?? new MsalAuthProviderOption();
        }
    }
}
