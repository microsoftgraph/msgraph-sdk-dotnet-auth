// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth
{
    using Microsoft.Identity.Client;

    internal class GraphAccount : IAccount
    {
        public GraphAccount(GraphUserAccount graphUserAccount)
        {
            if (graphUserAccount != null)
            {
                Username = graphUserAccount.Email;
                Environment = graphUserAccount.Environment;
                HomeAccountId = new AccountId($"{graphUserAccount.ObjectId}.{graphUserAccount.TenantId}", graphUserAccount.ObjectId, graphUserAccount.TenantId);
            }
        }
        public string Username { get; private set; }

        public string Environment { get; private set; }

        public AccountId HomeAccountId { get; private set; }
    }
}
