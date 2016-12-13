using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed
{
    public class SecureManagedPipeline : IPipelineConnection
    {
        private readonly IPipelineConnection _lowerConnection;
        private readonly Pipe _outputPipeline;
        private readonly Pipe _inputPipeline;
        private TaskCompletionSource<ApplicationLayerProtocolIds> _handShakeCompleted = new TaskCompletionSource<ApplicationLayerProtocolIds>();
        private readonly ManagedSecurityContext _securityContext;
        private ConnectionState _connectionState;

        public SecureManagedPipeline(IPipelineConnection inConnection, PipelineFactory factory, ManagedSecurityContext securityContext)
        {
            _lowerConnection = inConnection;
            _inputPipeline = factory.Create();
            _outputPipeline = factory.Create();
            _securityContext = securityContext;
            _connectionState = new ConnectionState();
        }

        public IPipelineReader Input => _outputPipeline;
        public IPipelineWriter Output => _inputPipeline;

        private async void StartReading()
        {
            try
            {
                while (true)
                {
                    var result = await _lowerConnection.Input.ReadAsync();
                    var buffer = result.Buffer;
                    try
                    {
                        if (buffer.IsEmpty && result.IsCompleted)
                        {
                            new InvalidOperationException("Connection closed before the handshake completed");
                        }
                        ReadableBuffer messageBuffer;
                        TlsFrameType frameType;
                        while (TryGetFrameType(ref buffer, out messageBuffer, out frameType))
                        {
                            _connectionState.CheckForValidFrameType(frameType);
                            _connectionState.DecryptRecord(ref messageBuffer);

                            if(frameType == TlsFrameType.AppData)
                            {
                                var outBuffer = _outputPipeline.Alloc();
                                outBuffer.Append(messageBuffer);
                                await outBuffer.FlushAsync();
                            }
                            else if(frameType == TlsFrameType.Handshake)
                            {
                                await _connectionState.ProcessHandshakeAsync(messageBuffer, _lowerConnection.Output);
                            }
                            else
                            {
                                throw new InvalidOperationException("HUH????");
                            }
                        }
                    }
                    catch { }
                    }
            }
            catch
            { }
        }
        
        public void Dispose()
        {
        }

        /// <summary>
        /// Checks to see if we have enough data for a frame and if the basic frame header is valid.
        /// </summary>
        /// <param name="buffer">The input buffer, it will be returned with the frame sliced out if there is a complete frame found</param>
        /// <param name="messageBuffer">If a frame is found this contains that frame</param>
        /// <param name="frameType">The type of frame that was detected</param>
        /// <returns>The status of the check for frame</returns>
        internal static bool TryGetFrameType(ref ReadableBuffer buffer, out ReadableBuffer messageBuffer,
            out TlsFrameType frameType)
        {
            frameType = TlsFrameType.Incomplete;
            //Need at least 5 bytes to be useful
            if (buffer.Length < 5)
            {
                messageBuffer = default(ReadableBuffer);
                return false;
            }
            frameType = (TlsFrameType)buffer.ReadBigEndian<byte>();

            //Check it's a valid frametype for what we are expecting
            if (frameType != TlsFrameType.AppData && frameType != TlsFrameType.Alert
                && frameType != TlsFrameType.ChangeCipherSpec && frameType != TlsFrameType.Handshake)
            {
                throw new FormatException($"The tls frame type was invalid value was {frameType}");
            }
            //now we get the version
            var version = (TlsVersion) buffer.Slice(1).ReadBigEndian<ushort>();

            if (!Enum.IsDefined(typeof(TlsVersion),version))
            {
                messageBuffer = default(ReadableBuffer);
                throw new FormatException($"The tls frame type was invalid due to the version value was {frameType}");
            }
            var length = buffer.Slice(3).ReadBigEndian<ushort>();
            // If we have a full frame slice it out and move the original buffer forward
            if (buffer.Length >= (length + 5))
            {
                //No need for the header anymore!
                messageBuffer = buffer.Slice(5, length);
                buffer = buffer.Slice(messageBuffer.End);
                return true;
            }
            messageBuffer = default(ReadableBuffer);
            return false;
        }
    }
}
