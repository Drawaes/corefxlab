using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.KeyExchange;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Internal.ManagedTls
{
    public class InteropCurves
    {
        private static readonly List<string> _availableCurves = new List<string>() {
            "secP160k1", "secP160r1", "secP160r2", "secP192k1", "secP192r1", "secP224k1",
            "secP224r1", "secP256k1", "secP256r1", "secP384r1", "secP521r1"};

        public static string MapTlsCurve(EllipticCurves exchange)
        {
            if (_availableCurves.Contains(exchange.ToString()))
            {
                return exchange.ToString();
            }
            return null;
        }

    }
}
