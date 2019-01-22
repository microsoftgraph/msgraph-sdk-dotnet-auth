using System;
using System.Collections.Generic;
using System.Text;

namespace Microsoft.Graph.Auth
{
    public enum NationalCloud
    {
        Global,
        China,
        Germany,
        UsGovernment
    }
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
            { NationalCloud.Global, "https://login.microsoftonline.com/{0}" },
            { NationalCloud.China, "https://login.chinacloudapi.cn/{0}" },
            { NationalCloud.Germany, "https://login.microsoftonline.de/{0}" },
            { NationalCloud.UsGovernment, "https://login.microsoftonline.us/{0}" }
        };
    }
}
