namespace CodeCube.Azure.KeyVault
{
    public sealed class SecretValue
    {
        public SecretValue(string value)
        {
            Value = value;
        }

        public string Value { get; }
    }
}
