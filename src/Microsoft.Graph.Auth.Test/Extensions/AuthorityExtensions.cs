using Microsoft.Identity.Client;
using System;
using System.Globalization;

namespace Microsoft.Graph.Auth.Test.Extensions
{
    internal static class AuthorityExtensions
    {
        public static string GetAuthorityUrl(this AzureCloudInstance azureCloudInstance, AadAuthorityAudience authorityAudience = default(AadAuthorityAudience), string tenantId = null)
        {
            return String.Format(CultureInfo.InvariantCulture, "{0}/{1}/", GetCloudUri(), GetAudienceUri());
            
            string GetAudienceUri()
            {
                return (authorityAudience, tenantId) switch
                {
                    (AadAuthorityAudience.AzureAdAndPersonalMicrosoftAccount, _) => "common",
                    (AadAuthorityAudience.AzureAdMultipleOrgs, _) => "organizations",
                    (AadAuthorityAudience.PersonalMicrosoftAccount, _) => "consumers",
                    (AadAuthorityAudience.AzureAdMyOrg, _) when !String.IsNullOrWhiteSpace(tenantId) => tenantId,
                    (AadAuthorityAudience.AzureAdMyOrg, _) when String.IsNullOrWhiteSpace(tenantId) => throw new ArgumentException(nameof(tenantId)),
                    (_, _) => throw new ArgumentException(nameof(authorityAudience))
                };
            }

            string GetCloudUri()
            {
                return azureCloudInstance switch
                {
                    AzureCloudInstance.AzurePublic => "https://login.microsoftonline.com",
                    AzureCloudInstance.AzureChina => "https://login.chinacloudapi.cn",
                    AzureCloudInstance.AzureGermany => "https://login.microsoftonline.de",
                    AzureCloudInstance.AzureUsGovernment => "https://login.microsoftonline.us",
                    _ => throw new ArgumentException(nameof(azureCloudInstance))
                };
            }
        }
    }
}