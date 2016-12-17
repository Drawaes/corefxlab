using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Alerts;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed
{
    public class SecureManagedPipeline : IPipelineConnection
    {
        private IPipelineConnection _lowerConnection;
        private readonly Pipe _outputPipeline;
        private readonly Pipe _inputPipeline;
        private TaskCompletionSource<ApplicationLayerProtocolIds> _handShakeCompleted = new TaskCompletionSource<ApplicationLayerProtocolIds>();
        private readonly ManagedSecurityContext _securityContext;
        private ConnectionState _connectionState;
        private bool _disposed;

        public SecureManagedPipeline(IPipelineConnection inConnection, PipelineFactory factory, ManagedSecurityContext securityContext)
        {
            _lowerConnection = inConnection;
            _inputPipeline = factory.Create();
            _outputPipeline = factory.Create();
            _securityContext = securityContext;
            _connectionState = new ConnectionState(securityContext, this);
            StartReading();
        }

        public IPipelineReader Input => _outputPipeline;
        public IPipelineWriter Output => _inputPipeline;
        public ApplicationLayerProtocolIds NegotiatedProtocol { get; internal set; }

        public Task<ApplicationLayerProtocolIds> PerformHandshakeAsync()
        {
            return _handShakeCompleted.Task;
        }

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

                            if (frameType == TlsFrameType.AppData)
                            {
                                var outBuffer = _outputPipeline.Alloc();
                                outBuffer.Write(messageBuffer.ToArray());
                                //outBuffer.Append(messageBuffer);
                                //outBuffer.Commit();
                                await outBuffer.FlushAsync();
                            }
                            else if (frameType == TlsFrameType.Handshake)
                            {
                                try
                                {
                                    await _connectionState.ProcessHandshakeAsync(messageBuffer, _lowerConnection.Output);
                                    if (_connectionState.HashshakeComplete)
                                    {
                                        _handShakeCompleted.TrySetResult(ApplicationLayerProtocolIds.None);
                                    }
                                }
                                catch (AlertException alert)
                                {
                                    var outBuffer = _lowerConnection.Output.Alloc();
                                    alert.WriteToOutput(ref outBuffer, _connectionState);
                                    await outBuffer.FlushAsync();
                                    throw;
                                }
                            }
                            else if (frameType == TlsFrameType.ChangeCipherSpec)
                            {
                                _connectionState.ClientDataEncrypted = true;
                            }
                            else
                            {
                                throw new InvalidOperationException("HUH????");
                            }
                        }
                    }
                    finally
                    {
                        _lowerConnection.Input.Advance(buffer.Start, buffer.End);
                    }
                }
            }
            catch (Exception ex)
            {
                _handShakeCompleted.TrySetException(ex);
                throw;
            }
        }

        private async Task StartWriting()
        {
            var maxBlockSize = _connectionState.MaxPlainText;
            while (true)
            {
                var result = await _inputPipeline.ReadAsync();
                var buffer = result.Buffer;
                if (buffer.IsEmpty && result.IsCompleted)
                {
                    break;
                }
                try
                {
                    while (buffer.Length > 0)
                    {
                        ReadableBuffer messageBuffer;
                        if (buffer.Length <= maxBlockSize)
                        {
                            messageBuffer = buffer;
                            buffer = buffer.Slice(buffer.End);
                        }
                        else
                        {
                            messageBuffer = buffer.Slice(0, maxBlockSize);
                            buffer = buffer.Slice(maxBlockSize);
                        }
                        await _connectionState.EncryptApplicationFrame(messageBuffer, _lowerConnection.Output);
                    }
                }
                finally
                {
                    _inputPipeline.Advance(buffer.End);
                }
            }
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
            var version = (TlsVersion)buffer.Slice(1).ReadBigEndian<ushort>();

            if (!Enum.IsDefined(typeof(TlsVersion), version))
            {
                messageBuffer = default(ReadableBuffer);
                throw new FormatException($"The tls frame type was invalid due to the version value was {frameType}");
            }
            var length = buffer.Slice(3).ReadBigEndian<ushort>();
            // If we have a full frame slice it out and move the original buffer forward
            if (buffer.Length >= (length + 5))
            {
                //We need the header for message validation
                messageBuffer = buffer.Slice(0, length + 5);
                buffer = buffer.Slice(messageBuffer.End);
                return true;
            }
            messageBuffer = default(ReadableBuffer);
            return false;
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _disposed = true;
                _outputPipeline.CompleteWriter();
                _inputPipeline.CompleteReader();
                _connectionState.Dispose();
                GC.SuppressFinalize(this);
            }
        }

        ~SecureManagedPipeline()
        {
            _connectionState.Dispose();
        }
    }
}
