// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.

using System;
using System.Collections.Generic;
//using System.Security.Cryptography;

namespace Microsoft.Azure.KeyVault.WebKey
{
    /// <summary>
    /// Because the current version of ECC is not supporting some of the operations needed for WebKey,
    /// those operations are added as ECC extension.
    /// </summary>
    public static class EccExtension
    {
        /// <summary>
        /// Exports EC parameters from a CNG object.
        /// </summary>
        /// <param name="ecdsa">The CNG object initialized with desired key</param>
        /// <param name="includePrivateParameters">Determines whether the private key part is to be exported.</param>
        /// <returns></returns>
        public static Microsoft.Azure.KeyVault.WebKey.ECParameters ExportParameters( this System.Security.Cryptography.ECDsa ecdsa, bool includePrivateParameters )
        {
            var ecdsaCng = GetEcdsaCng( ecdsa );
            return ECParameters.FromEcdsa( ecdsaCng, includePrivateParameters );
        }

        public static string[] GetKeyOperations( this System.Security.Cryptography.ECDsa ecdsa )
        {
            var keyUsage = GetEcdsaCng( ecdsa ).Key.KeyUsage;

            if ( !_cngOperations.ContainsKey( keyUsage ) )
                throw new System.Security.Cryptography.CryptographicException( $"Unknown key usage {keyUsage}" );

            return (string[]) _cngOperations[keyUsage].Clone();
        }

        private static System.Security.Cryptography.ECDsaCng GetEcdsaCng(System.Security.Cryptography.ECDsa ecdsa )
        {
            var ecdsaCng = ecdsa as System.Security.Cryptography.ECDsaCng;
            if ( ecdsaCng == null )
                throw new NotSupportedException( $"This version requires a CNG object." );
            return ecdsaCng;
        }

        private static readonly Dictionary<System.Security.Cryptography.CngKeyUsages, string[]> _cngOperations;

        static EccExtension()
        {
            _cngOperations = new Dictionary<System.Security.Cryptography.CngKeyUsages, string[]>
            {
                {System.Security.Cryptography.CngKeyUsages.None, new string[0]},
                {System.Security.Cryptography.CngKeyUsages.Signing, new[] {JsonWebKeyOperation.Sign, JsonWebKeyOperation.Verify}},
                {System.Security.Cryptography.CngKeyUsages.Decryption, new[] {JsonWebKeyOperation.Encrypt, JsonWebKeyOperation.Decrypt, JsonWebKeyOperation.Wrap, JsonWebKeyOperation.Unwrap}},
                {System.Security.Cryptography.CngKeyUsages.AllUsages, JsonWebKeyOperation.AllOperations}
            };
        }
    }
}