using System;
using Microsoft.Graph.Auth.Helpers;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Graph.Auth.Test.Helpers
{
    [TestClass]
    public class NationalCloudHelpersTests
    {
        [TestMethod]
        public void GetAuthority_ShouldGetAuthorityForNationalCloud()
        {
            string authority = NationalCloudHelpers.GetAuthority(NationalCloud.UsGovernment, "test");

            Assert.AreEqual("https://login.microsoftonline.us/test/", authority);
        }
    }
}
