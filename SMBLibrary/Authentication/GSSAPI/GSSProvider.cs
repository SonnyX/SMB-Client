/* Copyright (C) 2017-2018 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;
using System.Linq;
using SMBLibrary.Authentication.NTLM;
using Utilities;

namespace SMBLibrary.Authentication.GssApi
{
    public class GssProvider
    {
        public static readonly byte[] NtlmSspIdentifier = { 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a };

        private readonly List<IGssMechanism> m_mechanisms;

        public GssProvider(IGssMechanism mechanism)
        {
            m_mechanisms = new List<IGssMechanism> { mechanism };
        }

        public GssProvider(List<IGssMechanism> mechanisms)
        {
            m_mechanisms = mechanisms;
        }

        public byte[] GetSpnegoTokenInitBytes()
        {
            SimpleProtectedNegotiationTokenInit token = new SimpleProtectedNegotiationTokenInit
            {
                MechanismTypeList = new List<byte[]>()
            };
            foreach (IGssMechanism mechanism in m_mechanisms)
            {
                token.MechanismTypeList.Add(mechanism.Identifier);
            }
            return token.GetBytes(true);
        }

        public virtual NTStatus AcceptSecurityContext(ref GssContext? context, byte[] inputToken, out byte[]? outputToken)
        {
            outputToken = null;
            SimpleProtectedNegotiationToken? spnegoToken = null;
            try
            {
                spnegoToken = SimpleProtectedNegotiationToken.ReadToken(inputToken, 0, false);
            }
            catch
            {
                // ignored
            }

            if (spnegoToken != null)
            {
                if (spnegoToken is SimpleProtectedNegotiationTokenInit tokenInit)
                {
                    if (tokenInit.MechanismTypeList.Count == 0)
                    {
                        return NTStatus.SEC_E_INVALID_TOKEN;
                    }

                    // RFC 4178: Note that in order to avoid an extra round trip, the first context establishment token
                    // of the initiator's preferred mechanism SHOULD be embedded in the initial negotiation message.
                    byte[] preferredMechanism = tokenInit.MechanismTypeList[0];
                    IGssMechanism? mechanism = FindMechanism(preferredMechanism);
                    bool isPreferredMechanism = (mechanism != null);
                    if (!isPreferredMechanism)
                    {
                        mechanism = FindMechanism(tokenInit.MechanismTypeList);
                    }

                    if (mechanism == null)
                        return NTStatus.SEC_E_SECPKG_NOT_FOUND;
                    NTStatus status;
                    context = new GssContext(mechanism, null);
                    if (isPreferredMechanism)
                    {
                        status = mechanism.AcceptSecurityContext(ref context.MechanismContext, tokenInit.MechanismToken, out byte[] mechanismOutput);
                        outputToken = GetSpnegoTokenResponseBytes(mechanismOutput, status, mechanism.Identifier);
                    }
                    else
                    {
                        status = NTStatus.SEC_I_CONTINUE_NEEDED;
                        outputToken = GetSpnegoTokenResponseBytes(null, status, mechanism.Identifier);
                    }
                    return status;
                }
                else // SimpleProtectedNegotiationTokenResponse
                {
                    if (context == null)
                    {
                        return NTStatus.SEC_E_INVALID_TOKEN;
                    }
                    IGssMechanism mechanism = context.Mechanism;
                    SimpleProtectedNegotiationTokenResponse tokenResponse = (SimpleProtectedNegotiationTokenResponse)spnegoToken;
                    NTStatus status = mechanism.AcceptSecurityContext(ref context.MechanismContext, tokenResponse.ResponseToken, out byte[] mechanismOutput);
                    outputToken = GetSpnegoTokenResponseBytes(mechanismOutput, status, null);
                    return status;
                }
            }

            // [MS-SMB] The Windows GSS implementation supports raw Kerberos / NTLM messages in the SecurityBlob.
            // [MS-SMB2] Windows [..] will also accept raw Kerberos messages and implicit NTLM messages as part of GSS authentication.
            if (!AuthenticationMessageUtils.IsSignatureValid(inputToken))
                return NTStatus.SEC_E_INVALID_TOKEN;

            MessageTypeName messageType = AuthenticationMessageUtils.GetMessageType(inputToken);
            IGssMechanism? ntlmAuthenticationProvider = FindMechanism(NtlmSspIdentifier);
            if (ntlmAuthenticationProvider == null)
                return NTStatus.SEC_E_SECPKG_NOT_FOUND;

            if (messageType == MessageTypeName.Negotiate)
            {
                context = new GssContext(ntlmAuthenticationProvider, null);
            }

            if (context == null)
            {
                return NTStatus.SEC_E_INVALID_TOKEN;
            }
            
            return ntlmAuthenticationProvider.AcceptSecurityContext(ref context.MechanismContext, inputToken, out outputToken);

        }

        public virtual object? GetContextAttribute(GssContext? context, GssAttributeName attributeName)
        {
            IGssMechanism? mechanism = context?.Mechanism;
            return mechanism?.GetContextAttribute(context?.MechanismContext, attributeName);
        }

        public virtual bool DeleteSecurityContext(ref GssContext? context)
        {
            if (context == null)
                return false;
            IGssMechanism mechanism = context.Mechanism;
            return mechanism.DeleteSecurityContext(ref context.MechanismContext);
        }

        /// <summary>
        /// Helper method for legacy implementation.
        /// </summary>
        public virtual NTStatus GetNtlmChallengeMessage(out GssContext? context, NegotiateMessage negotiateMessage, out ChallengeMessage? challengeMessage)
        {
            IGssMechanism? ntlmAuthenticationProvider = FindMechanism(NtlmSspIdentifier);
            if (ntlmAuthenticationProvider != null)
            {
                context = new GssContext(ntlmAuthenticationProvider, null);
                NTStatus result = ntlmAuthenticationProvider.AcceptSecurityContext(ref context.MechanismContext, negotiateMessage.GetBytes(), out byte[] outputToken);
                challengeMessage = new ChallengeMessage(outputToken);
                return result;
            }

            context = null;
            challengeMessage = null;
            return NTStatus.SEC_E_SECPKG_NOT_FOUND;
        }

        /// <summary>
        /// Helper method for legacy implementation.
        /// </summary>
        public virtual NTStatus NtlmAuthenticate(GssContext? context, AuthenticateMessage authenticateMessage)
        {
            if (context == null || !ByteUtils.AreByteArraysEqual(context.Mechanism.Identifier, NtlmSspIdentifier))
                return NTStatus.SEC_E_SECPKG_NOT_FOUND;

            IGssMechanism mechanism = context.Mechanism;
            NTStatus result = mechanism.AcceptSecurityContext(ref context.MechanismContext, authenticateMessage.GetBytes(), out _);
            return result;
        }

        public IGssMechanism? FindMechanism(List<byte[]> mechanismIdentifiers)
        {
            return mechanismIdentifiers.Select(identifier => FindMechanism(identifier)).FirstOrDefault(mechanism => mechanism != null);
        }

        public IGssMechanism? FindMechanism(byte[] mechanismIdentifier)
        {
            return m_mechanisms.FirstOrDefault(mechanism => ByteUtils.AreByteArraysEqual(mechanism.Identifier, mechanismIdentifier));
        }

        private static byte[] GetSpnegoTokenResponseBytes(byte[] mechanismOutput, NTStatus status, byte[]? mechanismIdentifier)
        {
            SimpleProtectedNegotiationTokenResponse tokenResponse = new SimpleProtectedNegotiationTokenResponse();
            if (status == NTStatus.STATUS_SUCCESS)
            {
                tokenResponse.NegState = NegState.AcceptCompleted;
            }
            else if (status == NTStatus.SEC_I_CONTINUE_NEEDED)
            {
                tokenResponse.NegState = NegState.AcceptIncomplete;
            }
            else
            {
                tokenResponse.NegState = NegState.Reject;
            }
            tokenResponse.SupportedMechanism = mechanismIdentifier;
            tokenResponse.ResponseToken = mechanismOutput;
            return tokenResponse.GetBytes();
        }
    }
}