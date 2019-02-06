// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth.Helpers
{
    using System;
    using System.Globalization;
    public static class NationalCloudHelpers
    {
        internal static string GetAuthority(NationalCloud nationalCloud, string tenant)
        {
            string cloudUrl = string.Empty;
            if (!AuthConstants.CloudList.TryGetValue(nationalCloud, out cloudUrl))
            {
                throw new ArgumentException($" {nationalCloud} is an unexpected national cloud type");
            }

            return string.Format(CultureInfo.InvariantCulture, cloudUrl, tenant);
        }
    }
}
