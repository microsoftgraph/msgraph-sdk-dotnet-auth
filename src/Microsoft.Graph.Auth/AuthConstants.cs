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

        internal static Dictionary<NationalCloud, string> CloudList = new Dictionary<NationalCloud, string>
        {
            { NationalCloud.Global, "https://login.microsoftonline.com/{0}/" },
            { NationalCloud.China, "https://login.chinacloudapi.cn/{0}/" },
            { NationalCloud.Germany, "https://login.microsoftonline.de/{0}/" },
            { NationalCloud.UsGovernment, "https://login.microsoftonline.us/{0}/" }
        };
    }
}
