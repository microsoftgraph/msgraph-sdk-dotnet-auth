// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.Graph.Auth.Helpers
{
    using Newtonsoft.Json;
    using System;
    using System.Text;

    internal static class JwtHelpers
    {
        internal static string Decode(string jwToken)
        {
            var output = jwToken;
            output = output.Replace('-', '+');
            output = output.Replace('_', '/');
            switch (output.Length % 4) // Handle pad chars
            {
                case 0:
                    break;
                case 2:
                    output += "==";
                    break;
                case 3:
                    output += "=";
                    break;
                default:
                    throw new GraphAuthException(
                        new Error
                        {
                            Code = ErrorConstants.Codes.InvalidJWT,
                            Message = ErrorConstants.Message.InvalidJWT
                        });
            }

            return Encoding.UTF8.GetString(Convert.FromBase64String(output));
        }

        internal static T DecodeToObject<T>(string jwtString)
        {
            try
            {
                return JsonConvert.DeserializeObject<T>(Decode(jwtString));
            }
            catch (Exception ex)
            {
                throw new GraphAuthException(
                        new Error
                        {
                            Code = ErrorConstants.Codes.InvalidJWT,
                            Message = ErrorConstants.Message.InvalidJWT
                        }, ex);
            }
        }
    }
}
