using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.TlsSpec;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls.Managed
{
    public class SecurePipeline : IPipelineConnection
    {
        private IPipelineConnection _lowerConnection;
        private SecurePipelineListener _parentContext;
        private readonly Pipe _outputPipe;
        private readonly Pipe _inputPipe;
        private readonly Pipe _handshakePipe;
        private ConnectionStateFactory _currentConnectionState;
        private TaskCompletionSource<bool> _finished = new TaskCompletionSource<bool>();

        public IPipelineReader Input => _outputPipe;
        public IPipelineWriter Output => _inputPipe;

        public SecurePipeline(IPipelineConnection pipeline, PipelineFactory factory, SecurePipelineListener parentContext)
        {
            _lowerConnection = pipeline;
            _parentContext = parentContext;
            _outputPipe = factory.Create();
            _inputPipe = factory.Create();
            _handshakePipe = factory.Create();
            _currentConnectionState = new ConnectionStateFactory(_handshakePipe, _lowerConnection.Output, parentContext.CipherList);
            StartReading();
        }

        public Task<bool> Finished => _finished.Task;

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
                            break;
                        }
                        ReadableBuffer messageBuffer;
                        TlsFrameType frameType;
                        while (TryGetFrameType(ref buffer, out messageBuffer, out frameType))
                        {
                            switch (frameType)
                            {
                                case TlsFrameType.AppData:
                                    await _currentConnectionState.DecryptFrame(messageBuffer, _outputPipe);
                                    break;
                                case TlsFrameType.ChangeCipherSpec:
                                    await _currentConnectionState.ChangeCipher();
                                    break;
                                case TlsFrameType.Handshake:
                                    await _currentConnectionState.DecryptFrame(messageBuffer, _handshakePipe);
                                    if (_currentConnectionState.EncryptingServer)
                                    {
                                        StartWriting();
                                    }
                                    break;
                                case TlsFrameType.Alert:
                                    await _currentConnectionState.DecryptFrame(messageBuffer, _handshakePipe);
                                    throw new NotImplementedException();
                                case TlsFrameType.Invalid:
                                default:
                                    //Need to handle
                                    throw new NotImplementedException();
                            }
                        }
                    }
                    finally
                    {
                        _lowerConnection.Input.Advance(buffer.Start, buffer.End);
                    }
                }
            }
            finally
            {
                try
                {
                    //Close down the lower pipeline
                    _lowerConnection.Input.Complete();
                    _lowerConnection.Output.Complete();
                    //Tell the upper consumer that we aren't sending any more data
                    _outputPipe.CompleteReader();
                    _outputPipe.CompleteWriter();
                    _inputPipe.CompleteReader();
                    _inputPipe.CompleteWriter();
                }
                catch
                {
                    /*nom nom */
                }
            }
        }

        private async void StartWriting()
        {
            var maxBlockSize = _currentConnectionState.MaxContentSize;
            try
            {
                while (true)
                {
                    var result = await _inputPipe.ReadAsync();

                    var buffer = result.Buffer;
                    if (buffer.IsEmpty && result.IsCompleted)
                    {
                        break;
                    }
                    try
                    {
                        var writeBuffer = _lowerConnection.Output.Alloc();
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
                            FrameWriter fw = new FrameWriter(ref writeBuffer, TlsFrameType.AppData, _currentConnectionState.ConnectionState);
                            writeBuffer.Append(messageBuffer);
                            fw.Finish(ref writeBuffer);
                        }
                        await writeBuffer.FlushAsync();
                    }
                    finally
                    {
                        _inputPipe.Advance(buffer.End);
                    }
                }
            }
            finally
            {
                try
                {
                    //Close down the lower pipeline
                    _lowerConnection.Input.Complete();
                    _lowerConnection.Output.Complete();
                    //Tell the upper consumer that we aren't sending any more data
                    _outputPipe.CompleteReader();
                    _outputPipe.CompleteWriter();
                    _inputPipe.CompleteReader();
                    _inputPipe.CompleteWriter();
                }
                catch
                {
                    //            /*nom nom */
                }
            }
        }


        private static bool TryGetFrameType(ref ReadableBuffer buffer, out ReadableBuffer messageBuffer, out TlsFrameType frameType)
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
            var version = buffer.Slice(1).ReadBigEndian<ushort>();

            if (version < 0x300 || version >= 0x500)
            {
                messageBuffer = default(ReadableBuffer);
                throw new FormatException($"The tls frame type was invalid due to the version value was {frameType}");
            }
            var length = buffer.Slice(3).ReadBigEndian<ushort>();
            // If we have a full frame slice it out and move the original buffer forward
            if (buffer.Length >= (length + 5))
            {
                messageBuffer = buffer.Slice(0, length + 5);
                buffer = buffer.Slice(messageBuffer.End);
                return true;
            }
            messageBuffer = default(ReadableBuffer);
            return false;
        }

        ~SecurePipeline()
        {
            Dispose();
        }

        public void Dispose()
        {
            _lowerConnection.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}
