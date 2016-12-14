using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Certificates;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Windows;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed.Internal.KeyExchange
{
    internal class EcdhExchangeProvider : IKeyExchangeProvider
    {
        private ICertificate _certificate;
        private IntPtr _provider;
        private Dictionary<string, IntPtr> _providers = new Dictionary<string, IntPtr>(StringComparer.OrdinalIgnoreCase);
        private bool _isEphemeral;
        private static readonly string s_providerName = KeyExchangeType.ECDH.ToString();

        public EcdhExchangeProvider(ICertificate certificate, bool isEphemeral)
        {
            _isEphemeral = isEphemeral;
            _certificate = certificate;
            _provider = InteropProviders.OpenSecretProvider(s_providerName);
            foreach(var curve in InteropProperties.GetECCurveNameList(_provider))
            {
                _providers.Add(curve, IntPtr.Zero);
            }
        }

        public void Dispose()
        {
            lock(_providers)
            {
                foreach(var kv in _providers)
                {
                    try
                    {
                        if (kv.Value != IntPtr.Zero)
                        {
                            InteropProviders.CloseProvider(kv.Value);
                        }
                    }
                    catch { }
                }
                _providers.Clear();
            }
            InteropProviders.CloseProvider(_provider);
        }

        internal IntPtr GetProvider(EllipticCurves value)
        {
            lock(_providers)
            {
                var curveName = value.ToString();
                IntPtr provPtr;
                if(_providers.TryGetValue(curveName,out provPtr))
                {
                    if(provPtr == IntPtr.Zero)
                    {
                        provPtr = InteropProviders.OpenSecretProvider(s_providerName);
                        InteropProperties.SetEccCurveName(provPtr, curveName);
                        _providers[value.ToString()] = provPtr;
                        return provPtr;
                    }
                }
                return IntPtr.Zero;
            }
        }

        public override string ToString()
        {
            return "ECDHE_" + _certificate.CertificateType.ToString();
        }

        public IKeyExchangeInstance GetInstance(ConnectionState state)
        {
            if (_isEphemeral)
            {
                return new EcdheExchangeInstance(_certificate, state, this);
            }
            throw new NotImplementedException();
        }
    }
}
