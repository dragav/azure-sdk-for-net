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
    using Microsoft.Rest;
    using Microsoft.Rest.Serialization;
    using Newtonsoft.Json;
    using System.Collections;
    using System.Collections.Generic;
    using System.Linq;

    /// <summary>
    /// A common class for general resource information
    /// </summary>
    [Rest.Serialization.JsonTransformation]
    public partial class VirtualNetworkGateway : Resource
    {
        /// <summary>
        /// Initializes a new instance of the VirtualNetworkGateway class.
        /// </summary>
        public VirtualNetworkGateway()
        {
          CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the VirtualNetworkGateway class.
        /// </summary>
        /// <param name="id">Resource ID.</param>
        /// <param name="name">Resource name.</param>
        /// <param name="type">Resource type.</param>
        /// <param name="location">Resource location.</param>
        /// <param name="tags">Resource tags.</param>
        /// <param name="ipConfigurations">IP configurations for virtual
        /// network gateway.</param>
        /// <param name="gatewayType">The type of this virtual network gateway.
        /// Possible values are: 'Vpn' and 'ExpressRoute'. Possible values
        /// include: 'Vpn', 'ExpressRoute'</param>
        /// <param name="vpnType">The type of this virtual network gateway.
        /// Possible values are: 'PolicyBased' and 'RouteBased'. Possible
        /// values include: 'PolicyBased', 'RouteBased'</param>
        /// <param name="enableBgp">Whether BGP is enabled for this virtual
        /// network gateway or not.</param>
        /// <param name="activeActive">ActiveActive flag</param>
        /// <param name="gatewayDefaultSite">The reference of the
        /// LocalNetworkGateway resource which represents local network site
        /// having default routes. Assign Null value in case of removing
        /// existing default site setting.</param>
        /// <param name="sku">The reference of the VirtualNetworkGatewaySku
        /// resource which represents the SKU selected for Virtual network
        /// gateway.</param>
        /// <param name="vpnClientConfiguration">The reference of the
        /// VpnClientConfiguration resource which represents the P2S VpnClient
        /// configurations.</param>
        /// <param name="bgpSettings">Virtual network gateway's BGP speaker
        /// settings.</param>
        /// <param name="resourceGuid">The resource GUID property of the
        /// VirtualNetworkGateway resource.</param>
        /// <param name="provisioningState">The provisioning state of the
        /// VirtualNetworkGateway resource. Possible values are: 'Updating',
        /// 'Deleting', and 'Failed'.</param>
        /// <param name="etag">Gets a unique read-only string that changes
        /// whenever the resource is updated.</param>
        public VirtualNetworkGateway(string id = default(string), string name = default(string), string type = default(string), string location = default(string), IDictionary<string, string> tags = default(IDictionary<string, string>), IList<VirtualNetworkGatewayIPConfiguration> ipConfigurations = default(IList<VirtualNetworkGatewayIPConfiguration>), string gatewayType = default(string), string vpnType = default(string), bool? enableBgp = default(bool?), bool? activeActive = default(bool?), SubResource gatewayDefaultSite = default(SubResource), VirtualNetworkGatewaySku sku = default(VirtualNetworkGatewaySku), VpnClientConfiguration vpnClientConfiguration = default(VpnClientConfiguration), BgpSettings bgpSettings = default(BgpSettings), string resourceGuid = default(string), string provisioningState = default(string), string etag = default(string))
            : base(id, name, type, location, tags)
        {
            IpConfigurations = ipConfigurations;
            GatewayType = gatewayType;
            VpnType = vpnType;
            EnableBgp = enableBgp;
            ActiveActive = activeActive;
            GatewayDefaultSite = gatewayDefaultSite;
            Sku = sku;
            VpnClientConfiguration = vpnClientConfiguration;
            BgpSettings = bgpSettings;
            ResourceGuid = resourceGuid;
            ProvisioningState = provisioningState;
            Etag = etag;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets IP configurations for virtual network gateway.
        /// </summary>
        [JsonProperty(PropertyName = "properties.ipConfigurations")]
        public IList<VirtualNetworkGatewayIPConfiguration> IpConfigurations { get; set; }

        /// <summary>
        /// Gets or sets the type of this virtual network gateway. Possible
        /// values are: 'Vpn' and 'ExpressRoute'. Possible values include:
        /// 'Vpn', 'ExpressRoute'
        /// </summary>
        [JsonProperty(PropertyName = "properties.gatewayType")]
        public string GatewayType { get; set; }

        /// <summary>
        /// Gets or sets the type of this virtual network gateway. Possible
        /// values are: 'PolicyBased' and 'RouteBased'. Possible values
        /// include: 'PolicyBased', 'RouteBased'
        /// </summary>
        [JsonProperty(PropertyName = "properties.vpnType")]
        public string VpnType { get; set; }

        /// <summary>
        /// Gets or sets whether BGP is enabled for this virtual network
        /// gateway or not.
        /// </summary>
        [JsonProperty(PropertyName = "properties.enableBgp")]
        public bool? EnableBgp { get; set; }

        /// <summary>
        /// Gets or sets activeActive flag
        /// </summary>
        [JsonProperty(PropertyName = "properties.activeActive")]
        public bool? ActiveActive { get; set; }

        /// <summary>
        /// Gets or sets the reference of the LocalNetworkGateway resource
        /// which represents local network site having default routes. Assign
        /// Null value in case of removing existing default site setting.
        /// </summary>
        [JsonProperty(PropertyName = "properties.gatewayDefaultSite")]
        public SubResource GatewayDefaultSite { get; set; }

        /// <summary>
        /// Gets or sets the reference of the VirtualNetworkGatewaySku resource
        /// which represents the SKU selected for Virtual network gateway.
        /// </summary>
        [JsonProperty(PropertyName = "properties.sku")]
        public VirtualNetworkGatewaySku Sku { get; set; }

        /// <summary>
        /// Gets or sets the reference of the VpnClientConfiguration resource
        /// which represents the P2S VpnClient configurations.
        /// </summary>
        [JsonProperty(PropertyName = "properties.vpnClientConfiguration")]
        public VpnClientConfiguration VpnClientConfiguration { get; set; }

        /// <summary>
        /// Gets or sets virtual network gateway's BGP speaker settings.
        /// </summary>
        [JsonProperty(PropertyName = "properties.bgpSettings")]
        public BgpSettings BgpSettings { get; set; }

        /// <summary>
        /// Gets or sets the resource GUID property of the
        /// VirtualNetworkGateway resource.
        /// </summary>
        [JsonProperty(PropertyName = "properties.resourceGuid")]
        public string ResourceGuid { get; set; }

        /// <summary>
        /// Gets the provisioning state of the VirtualNetworkGateway resource.
        /// Possible values are: 'Updating', 'Deleting', and 'Failed'.
        /// </summary>
        [JsonProperty(PropertyName = "properties.provisioningState")]
        public string ProvisioningState { get; private set; }

        /// <summary>
        /// Gets a unique read-only string that changes whenever the resource
        /// is updated.
        /// </summary>
        [JsonProperty(PropertyName = "etag")]
        public string Etag { get; set; }

    }
}
