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

        public SecurePipelineConnection(IPipelineConnection pipeline, PipelineFactory factory)
        {
            _lowerConnection = pipeline;
            _outputPipe = factory.Create();
            _inputPipe = factory.Create();
            _recordHandler = new NullRecordHandler();
            _stateMachine = new TlsNull.NullStateMachine(this);
            StartReading();
        }

        public IPipelineReader Input => _outputPipe;
        public IPipelineWriter Output => _inputPipe;
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
                            switch (recordType)
                            {
                                case RecordType.Alert:
                                    _stateMachine.HandleAlert(messageBuffer, ref writeBuffer);
                                    break;
                                case RecordType.Application:
                                    _stateMachine.HandleAppData(messageBuffer, ref writeBuffer);
                                    break;
                                case RecordType.ChangeCipherSpec:
                                    _stateMachine.HandleChangeCipherSpec(messageBuffer, ref writeBuffer);
                                    break;
                                case RecordType.Handshake:
                                    _stateMachine.HandleHandshake(messageBuffer, ref writeBuffer);
                                    break;
                                default:
                                    Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error);
                                    break;
                            }
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
