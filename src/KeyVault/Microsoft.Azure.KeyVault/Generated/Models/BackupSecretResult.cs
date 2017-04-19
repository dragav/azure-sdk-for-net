// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//
// Code generated by Microsoft (R) AutoRest Code Generator 1.0.0.0
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.

namespace Microsoft.Azure.KeyVault.Models
{
    using Azure;
    using KeyVault;
    using Rest;
    using Rest.Serialization;
    using Newtonsoft.Json;
    using System.Linq;

    /// <summary>
    /// The backup secret result, containing the backup blob.
    /// </summary>
    public partial class BackupSecretResult
    {
        /// <summary>
        /// Initializes a new instance of the BackupSecretResult class.
        /// </summary>
        public BackupSecretResult() { }

        /// <summary>
        /// Initializes a new instance of the BackupSecretResult class.
        /// </summary>
        /// <param name="value">The backup blob containing the backed up
        /// secret.</param>
        public BackupSecretResult(byte[] value = default(byte[]))
        {
            Value = value;
        }

        /// <summary>
        /// Gets the backup blob containing the backed up secret.
        /// </summary>
        [JsonConverter(typeof(Base64UrlJsonConverter))]
        [JsonProperty(PropertyName = "value")]
        public byte[] Value { get; protected set; }

    }
}

