namespace Microsoft.Graph.Auth.Test.Extensions
{
    using Microsoft.Graph.Auth.Extensions;
    using Microsoft.Identity.Client;
    using System;
    using System.Collections.Generic;
    using Xunit;
    public class IClientApplicationBaseExtensionsTests
    {
        [Fact]
        public void ShouldSkipSettingAuthorityWhenWellKnownAuthoritiesAreSet()
        {
            string commonAuthority = AuthorityExtensions.GetAuthorityUrl(AzureCloudInstance.AzurePublic, AadAuthorityAudience.AzureAdAndPersonalMicrosoftAccount);
            string multiOrgAuthority = AuthorityExtensions.GetAuthorityUrl(AzureCloudInstance.AzureChina, AadAuthorityAudience.AzureAdMultipleOrgs);
            string msaAuthority = AuthorityExtensions.GetAuthorityUrl(AzureCloudInstance.AzureGermany, AadAuthorityAudience.PersonalMicrosoftAccount);

            string clientId = "00000000-0000-0000-0000-000000000000";

            IPublicClientApplication publicClientApplication = PublicClientApplicationBuilder
                .Create(clientId)
                .WithAuthority(multiOrgAuthority)
                .Build();

            Assert.True(IClientApplicationBaseExtensions.ContainsWellKnownTenantName(commonAuthority));
            Assert.True(IClientApplicationBaseExtensions.ContainsWellKnownTenantName(msaAuthority));
            Assert.True(IClientApplicationBaseExtensions.ContainsWellKnownTenantName(publicClientApplication.Authority));
        }

        [Fact]
        public void ShouldNotSkipSettingWhenCustomersTenantIsSet()
        {
            string tenantNameAuthority = AuthorityExtensions.GetAuthorityUrl(AzureCloudInstance.AzureChina, AadAuthorityAudience.AzureAdMyOrg, "commonOrg");
            string tenantGuidAuthority = AuthorityExtensions.GetAuthorityUrl(AzureCloudInstance.AzurePublic, AadAuthorityAudience.AzureAdMyOrg, Guid.NewGuid().ToString());

            string randomGuid = "00000000-0000-0000-0000-000000000000";

            IPublicClientApplication publicClientApplication = PublicClientApplicationBuilder
                .Create(randomGuid)
                .WithTenantId(randomGuid)
                .Build();

            Assert.False(IClientApplicationBaseExtensions.ContainsWellKnownTenantName(tenantNameAuthority));
            Assert.False(IClientApplicationBaseExtensions.ContainsWellKnownTenantName(tenantGuidAuthority));
            Assert.False(IClientApplicationBaseExtensions.ContainsWellKnownTenantName(publicClientApplication.Authority));
        }
    }
}
