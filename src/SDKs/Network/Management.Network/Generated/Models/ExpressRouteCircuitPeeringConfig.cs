// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//
// Code generated by Microsoft (R) AutoRest Code Generator 1.0.1.0
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.

namespace Microsoft.Azure.Management.Network.Models
{
    using Microsoft.Azure;
    using Microsoft.Azure.Management;
    using Microsoft.Azure.Management.Network;
    using Newtonsoft.Json;
    using System.Collections;
    using System.Collections.Generic;
    using System.Linq;

    /// <summary>
    /// Specifies the peering configuration.
    /// </summary>
    public partial class ExpressRouteCircuitPeeringConfig
    {
        /// <summary>
        /// Initializes a new instance of the ExpressRouteCircuitPeeringConfig
        /// class.
        /// </summary>
        public ExpressRouteCircuitPeeringConfig()
        {
          CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the ExpressRouteCircuitPeeringConfig
        /// class.
        /// </summary>
        /// <param name="advertisedPublicPrefixes">The reference of
        /// AdvertisedPublicPrefixes.</param>
        /// <param name="advertisedCommunities">The communities of bgp peering.
        /// Spepcified for microsoft peering</param>
        /// <param
        /// name="advertisedPublicPrefixesState">AdvertisedPublicPrefixState of
        /// the Peering resource. Possible values are 'NotConfigured',
        /// 'Configuring', 'Configured', and 'ValidationNeeded'. Possible
        /// values include: 'NotConfigured', 'Configuring', 'Configured',
        /// 'ValidationNeeded'</param>
        /// <param name="customerASN">The CustomerASN of the peering.</param>
        /// <param name="legacyMode">The legacy mode of the peering.</param>
        /// <param name="routingRegistryName">The RoutingRegistryName of the
        /// configuration.</param>
        public ExpressRouteCircuitPeeringConfig(IList<string> advertisedPublicPrefixes = default(IList<string>), IList<string> advertisedCommunities = default(IList<string>), string advertisedPublicPrefixesState = default(string), int? customerASN = default(int?), int? legacyMode = default(int?), string routingRegistryName = default(string))
        {
            AdvertisedPublicPrefixes = advertisedPublicPrefixes;
            AdvertisedCommunities = advertisedCommunities;
            AdvertisedPublicPrefixesState = advertisedPublicPrefixesState;
            CustomerASN = customerASN;
            LegacyMode = legacyMode;
            RoutingRegistryName = routingRegistryName;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets the reference of AdvertisedPublicPrefixes.
        /// </summary>
        [JsonProperty(PropertyName = "advertisedPublicPrefixes")]
        public IList<string> AdvertisedPublicPrefixes { get; set; }

        /// <summary>
        /// Gets or sets the communities of bgp peering. Spepcified for
        /// microsoft peering
        /// </summary>
        [JsonProperty(PropertyName = "advertisedCommunities")]
        public IList<string> AdvertisedCommunities { get; set; }

        /// <summary>
        /// Gets or sets advertisedPublicPrefixState of the Peering resource.
        /// Possible values are 'NotConfigured', 'Configuring', 'Configured',
        /// and 'ValidationNeeded'. Possible values include: 'NotConfigured',
        /// 'Configuring', 'Configured', 'ValidationNeeded'
        /// </summary>
        [JsonProperty(PropertyName = "advertisedPublicPrefixesState")]
        public string AdvertisedPublicPrefixesState { get; set; }

        /// <summary>
        /// Gets or sets the CustomerASN of the peering.
        /// </summary>
        [JsonProperty(PropertyName = "customerASN")]
        public int? CustomerASN { get; set; }

        /// <summary>
        /// Gets or sets the legacy mode of the peering.
        /// </summary>
        [JsonProperty(PropertyName = "legacyMode")]
        public int? LegacyMode { get; set; }

        /// <summary>
        /// Gets or sets the RoutingRegistryName of the configuration.
        /// </summary>
        [JsonProperty(PropertyName = "routingRegistryName")]
        public string RoutingRegistryName { get; set; }

    }
}
