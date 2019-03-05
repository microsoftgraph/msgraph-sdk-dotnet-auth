// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using System;
    using Newtonsoft.Json;

    public partial class JwtPayload
    {
        [JsonProperty("aud")]
        public Uri Aud { get; set; }

        [JsonProperty("iss")]
        public Uri Iss { get; set; }

        [JsonProperty("iat")]
        public long Iat { get; set; }

        [JsonProperty("nbf")]
        public long Nbf { get; set; }

        [JsonProperty("exp")]
        public long Exp { get; set; }

        [JsonProperty("acct")]
        public long Acct { get; set; }

        [JsonProperty("aio")]
        public string Aio { get; set; }

        [JsonProperty("amr")]
        public string[] Amr { get; set; }

        [JsonProperty("app_displayname")]
        public string AppDisplayname { get; set; }

        [JsonProperty("appid")]
        public Guid Appid { get; set; }

        [JsonProperty("deviceid")]
        public Guid Deviceid { get; set; }

        [JsonProperty("family_name")]
        public string FamilyName { get; set; }

        [JsonProperty("given_name")]
        public string GivenName { get; set; }

        [JsonProperty("ipaddr")]
        public string Ipaddr { get; set; }

        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("oid")]
        public Guid Oid { get; set; }

        [JsonProperty("puid")]
        public string Puid { get; set; }

        [JsonProperty("rh")]
        public string Rh { get; set; }

        [JsonProperty("scp")]
        public string Scp { get; set; }

        [JsonProperty("sub")]
        public string Sub { get; set; }

        [JsonProperty("tid")]
        public Guid Tid { get; set; }

        [JsonProperty("unique_name")]
        public string UniqueName { get; set; }

        [JsonProperty("upn")]
        public string Upn { get; set; }

        [JsonProperty("uti")]
        public string Uti { get; set; }

        [JsonProperty("ver")]
        public string Ver { get; set; }

        [JsonProperty("wids")]
        public Guid[] Wids { get; set; }

        [JsonProperty("xms_tcdt")]
        public long XmsTcdt { get; set; }
    }

}
