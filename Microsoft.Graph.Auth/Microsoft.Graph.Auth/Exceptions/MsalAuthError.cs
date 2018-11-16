using System;
using System.Collections.Generic;
using System.Text;

namespace Microsoft.Graph.Auth
{
    public class MsalAuthError
    {
        public MsalAuthErrorCode Code { get; set; }
        public string Message { get; set; }
    }
}
