namespace Microsoft.Graph.Auth.Test.Mocks
{
    using Microsoft.Identity.Client;
    using System;

    public class MockUserAccount : IAccount
    {
        private readonly string _username;
        private readonly string _environment;
        private readonly AccountId _accountId;

        public MockUserAccount(string username, string environment)
        {
            _username = username;
            _environment = environment;
            _accountId = new AccountId(username, Guid.NewGuid().ToString(), Guid.NewGuid().ToString());
        }
        public string Username => _username;

        public string Environment => _environment;

        public AccountId HomeAccountId => _accountId;
    }
}
