// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.

namespace Microsoft.Azure.Management.RecoveryServices.SiteRecovery.Models
{
    using Microsoft.Azure;
    using Microsoft.Azure.Management;
    using Microsoft.Azure.Management.RecoveryServices;
    using Microsoft.Azure.Management.RecoveryServices.SiteRecovery;
    using Newtonsoft.Json;
    using System.Linq;

    /// <summary>
    /// Configure pairing input properties.
    /// </summary>
    public partial class CreateProtectionContainerMappingInputProperties
    {
        /// <summary>
        /// Initializes a new instance of the
        /// CreateProtectionContainerMappingInputProperties class.
        /// </summary>
        public CreateProtectionContainerMappingInputProperties()
        {
          CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the
        /// CreateProtectionContainerMappingInputProperties class.
        /// </summary>
        /// <param name="targetProtectionContainerId">The target unique
        /// protection container name.</param>
        /// <param name="policyId">Applicable policy.</param>
        /// <param name="providerSpecificInput">Provider specific input for
        /// pairing.</param>
        public CreateProtectionContainerMappingInputProperties(string targetProtectionContainerId = default(string), string policyId = default(string), ReplicationProviderSpecificContainerMappingInput providerSpecificInput = default(ReplicationProviderSpecificContainerMappingInput))
        {
            TargetProtectionContainerId = targetProtectionContainerId;
            PolicyId = policyId;
            ProviderSpecificInput = providerSpecificInput;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets the target unique protection container name.
        /// </summary>
        [JsonProperty(PropertyName = "targetProtectionContainerId")]
        public string TargetProtectionContainerId { get; set; }

        /// <summary>
        /// Gets or sets applicable policy.
        /// </summary>
        [JsonProperty(PropertyName = "PolicyId")]
        public string PolicyId { get; set; }

        /// <summary>
        /// Gets or sets provider specific input for pairing.
        /// </summary>
        [JsonProperty(PropertyName = "providerSpecificInput")]
        public ReplicationProviderSpecificContainerMappingInput ProviderSpecificInput { get; set; }

    }
}
