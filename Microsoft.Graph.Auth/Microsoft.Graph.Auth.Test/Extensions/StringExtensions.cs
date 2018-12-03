namespace Microsoft.Graph.Auth.Test.Extensions
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;

    internal static class StringExtensions
    {
        public static byte[] ToByteArray(this string stringValue)
        {
            return new UTF8Encoding().GetBytes(stringValue);
        }
    }
}
