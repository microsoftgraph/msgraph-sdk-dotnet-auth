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
            // clean token chars
            string cleanToken = jwToken;
            cleanToken = cleanToken.Replace('-', '+');
            cleanToken = cleanToken.Replace('_', '/');
            switch (cleanToken.Length % 4) // Handle pad chars
            {
                case 0:
                    break;
                case 2:
                    cleanToken += "==";
                    break;
                case 3:
                    cleanToken += "=";
                    break;
                default:
                    throw new AuthenticationException(
                        new Error
                        {
                            Code = ErrorConstants.Codes.InvalidJWT,
                            Message = ErrorConstants.Message.InvalidJWT
                        });
            }

            return Encoding.UTF8.GetString(Convert.FromBase64String(cleanToken));
        }

        internal static T DecodeToObject<T>(string jwtString)
        {
            try
            {
                return JsonConvert.DeserializeObject<T>(Decode(jwtString));
            }
            catch (Exception ex)
            {
                throw new AuthenticationException(
                        new Error
                        {
                            Code = ErrorConstants.Codes.InvalidJWT,
                            Message = ErrorConstants.Message.InvalidJWT
                        }, ex);
            }
        }
    }
}
