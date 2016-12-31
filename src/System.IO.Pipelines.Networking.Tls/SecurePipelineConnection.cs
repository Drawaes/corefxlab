using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.RecordProtocol;
using System.Linq;
using System.Threading.Tasks;

namespace System.IO.Pipelines.Networking.Tls
{
    public class SecurePipelineConnection:IPipelineConnection
    {
        private readonly IPipelineConnection _lowerConnection;
        private IRecordHandler _recordHandler;
        private IStateMachine _stateMachine;
        private readonly Pipe _outputPipe;
        private readonly Pipe _inputPipe;
        private readonly SecurePipelineListener _listener;

        public SecurePipelineConnection(IPipelineConnection pipeline, PipelineFactory factory, SecurePipelineListener listener)
        {
            _listener = listener;
            _lowerConnection = pipeline;
            _outputPipe = factory.Create();
            _inputPipe = factory.Create();
            _recordHandler = new NullRecordHandler();
            _stateMachine = new TlsNull.NullStateMachine(this);
            StartReading();
        }

        public IPipelineReader Input => _outputPipe;
        public IPipelineWriter Output => _inputPipe;
        public SecurePipelineListener Listener => _listener;
        internal IRecordHandler RecordHandler { set { _recordHandler = value; } }
        internal IStateMachine StateMachine { set { _stateMachine = value; } }
        
        private async void StartReading()
        {
            while (true)
            {
                var result = await _lowerConnection.Input.ReadAsync();
                var buffer = result.Buffer;
                try
                {
                    ReadableBuffer messageBuffer;
                    while (RecordUtils.TryGetFrame(ref buffer, out messageBuffer))
                    {
                        var recordType = _recordHandler.ProcessRecord(ref messageBuffer);
                        var writeBuffer = _lowerConnection.Output.Alloc();
                        try
                        {
                            _stateMachine.HandleRecord(recordType, messageBuffer, ref writeBuffer);
                        }
                        finally
                        {
                            if(writeBuffer.BytesWritten == 0)
                            {
                                writeBuffer.Commit();
                            }
                            else
                            {
                                await writeBuffer.FlushAsync();
                            }
                        }
                    }
                }
                finally
                {
                    _lowerConnection.Input.Advance(buffer.Start, buffer.End);
                }
            }
        }

        ~SecurePipelineConnection()
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
