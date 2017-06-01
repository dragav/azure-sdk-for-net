// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.

namespace Microsoft.Azure.Management.RecoveryServices.SiteRecovery
{
    using Microsoft.Azure;
    using Microsoft.Azure.Management;
    using Microsoft.Azure.Management.RecoveryServices;
    using Microsoft.Rest;
    using Microsoft.Rest.Azure;
    using Models;
    using System.Threading;
    using System.Threading.Tasks;

    /// <summary>
    /// Extension methods for ReplicationPoliciesOperations.
    /// </summary>
    public static partial class ReplicationPoliciesOperationsExtensions
    {
            /// <summary>
            /// Gets the requested policy.
            /// </summary>
            /// <remarks>
            /// Gets the details of a replication policy.
            /// </remarks>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='policyName'>
            /// Replication policy name.
            /// </param>
            public static Policy Get(this IReplicationPoliciesOperations operations, string policyName)
            {
                return operations.GetAsync(policyName).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Gets the requested policy.
            /// </summary>
            /// <remarks>
            /// Gets the details of a replication policy.
            /// </remarks>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='policyName'>
            /// Replication policy name.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<Policy> GetAsync(this IReplicationPoliciesOperations operations, string policyName, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.GetWithHttpMessagesAsync(policyName, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Creates the policy.
            /// </summary>
            /// <remarks>
            /// The operation to create a replication policy
            /// </remarks>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='policyName'>
            /// Replication policy name
            /// </param>
            /// <param name='input'>
            /// Create policy input
            /// </param>
            public static Policy Create(this IReplicationPoliciesOperations operations, string policyName, CreatePolicyInput input)
            {
                return operations.CreateAsync(policyName, input).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Creates the policy.
            /// </summary>
            /// <remarks>
            /// The operation to create a replication policy
            /// </remarks>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='policyName'>
            /// Replication policy name
            /// </param>
            /// <param name='input'>
            /// Create policy input
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<Policy> CreateAsync(this IReplicationPoliciesOperations operations, string policyName, CreatePolicyInput input, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.CreateWithHttpMessagesAsync(policyName, input, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Delete the policy.
            /// </summary>
            /// <remarks>
            /// The operation to delete a replication policy.
            /// </remarks>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='policyName'>
            /// Replication policy name.
            /// </param>
            public static void Delete(this IReplicationPoliciesOperations operations, string policyName)
            {
                operations.DeleteAsync(policyName).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Delete the policy.
            /// </summary>
            /// <remarks>
            /// The operation to delete a replication policy.
            /// </remarks>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='policyName'>
            /// Replication policy name.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task DeleteAsync(this IReplicationPoliciesOperations operations, string policyName, CancellationToken cancellationToken = default(CancellationToken))
            {
                (await operations.DeleteWithHttpMessagesAsync(policyName, null, cancellationToken).ConfigureAwait(false)).Dispose();
            }

            /// <summary>
            /// Updates the protection profile.
            /// </summary>
            /// <remarks>
            /// The operation to update a replication policy.
            /// </remarks>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='policyName'>
            /// Protection profile Id.
            /// </param>
            /// <param name='input'>
            /// Update Protection Profile Input
            /// </param>
            public static Policy Update(this IReplicationPoliciesOperations operations, string policyName, UpdatePolicyInput input)
            {
                return operations.UpdateAsync(policyName, input).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Updates the protection profile.
            /// </summary>
            /// <remarks>
            /// The operation to update a replication policy.
            /// </remarks>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='policyName'>
            /// Protection profile Id.
            /// </param>
            /// <param name='input'>
            /// Update Protection Profile Input
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<Policy> UpdateAsync(this IReplicationPoliciesOperations operations, string policyName, UpdatePolicyInput input, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.UpdateWithHttpMessagesAsync(policyName, input, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Gets the list of replication policies
            /// </summary>
            /// <remarks>
            /// Lists the replication policies for a vault.
            /// </remarks>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            public static IPage<Policy> List(this IReplicationPoliciesOperations operations)
            {
                return operations.ListAsync().GetAwaiter().GetResult();
            }

            /// <summary>
            /// Gets the list of replication policies
            /// </summary>
            /// <remarks>
            /// Lists the replication policies for a vault.
            /// </remarks>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<IPage<Policy>> ListAsync(this IReplicationPoliciesOperations operations, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.ListWithHttpMessagesAsync(null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Creates the policy.
            /// </summary>
            /// <remarks>
            /// The operation to create a replication policy
            /// </remarks>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='policyName'>
            /// Replication policy name
            /// </param>
            /// <param name='input'>
            /// Create policy input
            /// </param>
            public static Policy BeginCreate(this IReplicationPoliciesOperations operations, string policyName, CreatePolicyInput input)
            {
                return operations.BeginCreateAsync(policyName, input).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Creates the policy.
            /// </summary>
            /// <remarks>
            /// The operation to create a replication policy
            /// </remarks>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='policyName'>
            /// Replication policy name
            /// </param>
            /// <param name='input'>
            /// Create policy input
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<Policy> BeginCreateAsync(this IReplicationPoliciesOperations operations, string policyName, CreatePolicyInput input, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.BeginCreateWithHttpMessagesAsync(policyName, input, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Delete the policy.
            /// </summary>
            /// <remarks>
            /// The operation to delete a replication policy.
            /// </remarks>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='policyName'>
            /// Replication policy name.
            /// </param>
            public static void BeginDelete(this IReplicationPoliciesOperations operations, string policyName)
            {
                operations.BeginDeleteAsync(policyName).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Delete the policy.
            /// </summary>
            /// <remarks>
            /// The operation to delete a replication policy.
            /// </remarks>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='policyName'>
            /// Replication policy name.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task BeginDeleteAsync(this IReplicationPoliciesOperations operations, string policyName, CancellationToken cancellationToken = default(CancellationToken))
            {
                (await operations.BeginDeleteWithHttpMessagesAsync(policyName, null, cancellationToken).ConfigureAwait(false)).Dispose();
            }

            /// <summary>
            /// Updates the protection profile.
            /// </summary>
            /// <remarks>
            /// The operation to update a replication policy.
            /// </remarks>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='policyName'>
            /// Protection profile Id.
            /// </param>
            /// <param name='input'>
            /// Update Protection Profile Input
            /// </param>
            public static Policy BeginUpdate(this IReplicationPoliciesOperations operations, string policyName, UpdatePolicyInput input)
            {
                return operations.BeginUpdateAsync(policyName, input).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Updates the protection profile.
            /// </summary>
            /// <remarks>
            /// The operation to update a replication policy.
            /// </remarks>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='policyName'>
            /// Protection profile Id.
            /// </param>
            /// <param name='input'>
            /// Update Protection Profile Input
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<Policy> BeginUpdateAsync(this IReplicationPoliciesOperations operations, string policyName, UpdatePolicyInput input, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.BeginUpdateWithHttpMessagesAsync(policyName, input, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Gets the list of replication policies
            /// </summary>
            /// <remarks>
            /// Lists the replication policies for a vault.
            /// </remarks>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='nextPageLink'>
            /// The NextLink from the previous successful call to List operation.
            /// </param>
            public static IPage<Policy> ListNext(this IReplicationPoliciesOperations operations, string nextPageLink)
            {
                return operations.ListNextAsync(nextPageLink).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Gets the list of replication policies
            /// </summary>
            /// <remarks>
            /// Lists the replication policies for a vault.
            /// </remarks>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='nextPageLink'>
            /// The NextLink from the previous successful call to List operation.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<IPage<Policy>> ListNextAsync(this IReplicationPoliciesOperations operations, string nextPageLink, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.ListNextWithHttpMessagesAsync(nextPageLink, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

    }
}
