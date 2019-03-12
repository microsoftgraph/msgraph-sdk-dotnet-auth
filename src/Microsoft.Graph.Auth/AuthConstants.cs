// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using System.Collections.Generic;
    internal static class AuthConstants
    {
        internal static class Tenants
        {
            public const string Common = "common";
            public const string Organizations = "organizations";
            public const string Consumers = "consumers";
        }
        internal static class ClaimTypes
        {
            public const string ObjectIdUriSchema = "http://schemas.microsoft.com/identity/claims/objectidentifier";
            public const string ObjectIdJwt = "oid";

            public const string TenantIdUriSchema = "http://schemas.microsoft.com/identity/claims/tenantid";
            public const string TenantIdJwt = "tid";

            public const string EmailUriSchema = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress";
            public const string EmailJwt = "preferred_username";
        }

        internal static Dictionary<NationalCloud, string> CloudList = new Dictionary<NationalCloud, string>
        {
            { NationalCloud.Global, "https://login.microsoftonline.com/{0}/" },
            { NationalCloud.China, "https://login.chinacloudapi.cn/{0}/" },
            { NationalCloud.Germany, "https://login.microsoftonline.de/{0}/" },
            { NationalCloud.UsGovernment, "https://login.microsoftonline.us/{0}/" }
        };
    }
}
