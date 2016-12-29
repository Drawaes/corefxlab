using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Windows;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.TlsSpec;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Windows;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.KeyExchange.Windows
{
    internal class EcdhExchangeProvider : IKeyExchangeProvider
    {
        private ICertificate _certificate;
        private SafeBCryptAlgorithmHandle _provider;
        private Dictionary<string, SafeBCryptAlgorithmHandle> _providers = new Dictionary<string, SafeBCryptAlgorithmHandle>(StringComparer.OrdinalIgnoreCase);
        private bool _isEphemeral;
        private static readonly string s_providerName = KeyExchangeType.ECDH.ToString();

        public EcdhExchangeProvider(ICertificate certificate, bool isEphemeral)
        {
            _isEphemeral = isEphemeral;
            _certificate = certificate;
            _provider = BCryptHelper.OpenSecretProvider(s_providerName);
            foreach (var curve in BCryptPropertiesHelper.GetECCurveNameList(_provider))
            {
                _providers.Add(curve, null);
            }
        }

        public ICertificate Certificate => _certificate;

        public IKeyExchangeInstance GetInstance(IConnectionState state)
        {
            if (_isEphemeral)
            {
                var instance = new EcdheExchangeInstance(state, this);
                instance.SetSignature(_certificate.GetHashandSignInstance(state.CipherSuite.Hash.HashType, PaddingType.Pkcs1),_certificate);
                return instance;
            }
            throw new NotImplementedException();
        }

        public override string ToString()
        {
            return "ECDHE_" + _certificate.CertificateType.ToString();
        }

        internal SafeBCryptAlgorithmHandle GetProvider(EllipticCurves value)
        {
            lock (_providers)
            {
                var curveName = value.ToString();
                SafeBCryptAlgorithmHandle provPtr;
                if (_providers.TryGetValue(curveName, out provPtr))
                {
                    if (provPtr == null)
                    {
                        provPtr = BCryptHelper.OpenSecretProvider(s_providerName);
                        BCryptPropertiesHelper.SetEccCurveName(provPtr, curveName);
                        _providers[value.ToString()] = provPtr;
                    }
                    return provPtr;
                }
                return null;
            }
        }

        public void Dispose()
        {
            lock (_providers)
            {
                foreach (var kv in _providers)
                {
                    kv.Value?.Dispose();
                }
                _providers.Clear();
            }
            _provider.Dispose();
        }
    }
}
