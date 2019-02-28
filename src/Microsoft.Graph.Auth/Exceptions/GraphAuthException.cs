namespace Microsoft.Graph.Auth
{
    using System;
    public class GraphAuthException : Exception
    {
        public GraphAuthException(Error error, Exception innerException = null)
            :base(error?.ToString(), innerException)
        {
            this.Error = error;
        }

        public Error Error { get; private set; }
    }
}
