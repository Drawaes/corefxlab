namespace System.IO.Pipelines.Networking.Tls.Hashes
{
    public interface IHashProvider
    {
        IHashInstance GetHashInstance(HashType hashType);
    }
}