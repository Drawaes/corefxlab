namespace System.IO.Pipelines.Networking.Tls
{
    /// <summary>
    /// Used when chopping the incoming stream into the correct frames
    /// </summary>
    public enum TlsFrameType : byte
    {
        ChangeCipherSpec = 20,
        Alert = 21,
        Handshake = 22,
        AppData = 23,
        Invalid = 255,
        Incomplete = 0
    }
}