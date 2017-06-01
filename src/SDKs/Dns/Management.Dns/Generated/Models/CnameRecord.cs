// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//
// Code generated by Microsoft (R) AutoRest Code Generator 1.0.0.0
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.

namespace Microsoft.Azure.Management.Dns.Models
{
    using Azure;
    using Management;
    using Dns;
    using Newtonsoft.Json;
    using System.Linq;

    /// <summary>
    /// A CNAME record.
    /// </summary>
    public partial class CnameRecord
    {
        /// <summary>
        /// Initializes a new instance of the CnameRecord class.
        /// </summary>
        public CnameRecord() { }

        /// <summary>
        /// Initializes a new instance of the CnameRecord class.
        /// </summary>
        /// <param name="cname">The canonical name for this CNAME
        /// record.</param>
        public CnameRecord(string cname = default(string))
        {
            Cname = cname;
        }

        /// <summary>
        /// Gets or sets the canonical name for this CNAME record.
        /// </summary>
        [JsonProperty(PropertyName = "cname")]
        public string Cname { get; set; }

    }
}

