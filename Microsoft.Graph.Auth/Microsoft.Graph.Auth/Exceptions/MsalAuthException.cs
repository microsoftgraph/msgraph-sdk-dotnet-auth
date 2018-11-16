using System;
using System.Collections.Generic;
using System.Text;

namespace Microsoft.Graph.Auth
{
    public class MsalAuthException: Exception
    {
        public MsalAuthException(MsalAuthError msalAuthError, Exception innerException = null)
            :base(msalAuthError?.ToString(), innerException)
        {
            Error = msalAuthError;
        }

        public MsalAuthError Error { get; set; }
    }
}
