namespace Microsoft.Graph.Auth.Test.Mocks
{
    using Microsoft.Graph.Auth.Test.Extensions;
    using Microsoft.Identity.Client;
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.IO;
    using System.Linq;
    using System.Runtime.Serialization.Json;
    using System.Text;
    public class StorageCacheItem
    {
        public string Environment { get; set; }
        public string ClientId { get; set; }
        public string TokenType { get; set; }
        public string Scopes { get; set; }
        public string TenantId { get; set; }
        public string Secret { get; set; }
        public DateTimeOffset AccessTokenExpiresOn { get; set; }
        public DateTimeOffset AccessTokenExtenedExpireOn { get; set; }
        public string RawClientInfo { get; set; }
    }

    internal class StorageMock
    {
        private TokenCache _cache = new TokenCache();
        private StorageCacheItem _storageCacheItem;
        private readonly IDictionary<string, string> _accessTokenCacheDictionary = new ConcurrentDictionary<string, string>();
        private readonly IEnumerable<string> _accessTokenAsString;
        private readonly Dictionary<string, IEnumerable<string>> _cacheDictionary;
        private readonly byte[] _cacheByte;

        public StorageMock(string accessTokenKey, StorageCacheItem accessTokenCacheItem)
        {
            _storageCacheItem = accessTokenCacheItem;
            _accessTokenCacheDictionary[accessTokenKey] = JsonHelper.SerializeToJson(accessTokenCacheItem);
            _accessTokenAsString = new ReadOnlyCollection<string>(_accessTokenCacheDictionary.Values.ToList());
            _cacheDictionary = new Dictionary<string, IEnumerable<string>>
            {
                [accessTokenKey] = _accessTokenAsString
            };
            _cacheByte = JsonHelper.SerializeToJson(_cacheDictionary).ToByteArray();
        }

        private void OnBeforeAccess(TokenCacheNotificationArgs args)
        {

        }

        private void OnAfterAccess(TokenCacheNotificationArgs args)
        {

        }
    }

    internal static class JsonHelper {
        internal static string SerializeToJson<T>(T data)
        {
            using (MemoryStream stream = new MemoryStream())
            {
                DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(T));
                serializer.WriteObject(stream, data);
                return Encoding.UTF8.GetString(stream.ToArray(), 0, (int)stream.Position);
            }
        }

        internal static T DeserializeFromJson<T>(string json)
        {
            if (string.IsNullOrEmpty(json))
            {
                return default(T);
            }

            return DeserializeFromJson<T>(json.ToByteArray());
        }

        internal static T DeserializeFromJson<T>(byte[] jsonByteArray)
        {
            if (jsonByteArray == null || jsonByteArray.Length == 0)
            {
                return default(T);
            }

            T response;
            DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(T));
            using (MemoryStream stream = new MemoryStream(jsonByteArray))
            {
                response = ((T)serializer.ReadObject(stream));
            }

            return response;
        }
    }
}
