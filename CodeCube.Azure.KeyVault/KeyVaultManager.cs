using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Azure.Services.AppAuthentication;

namespace CodeCube.Azure.KeyVault
{
    internal sealed class KeyVaultManager
    {
        private KeyVaultClient keyVaultClient { get; }

        public KeyVaultManager()
        {
            AzureServiceTokenProvider azureServiceTokenProvider = new AzureServiceTokenProvider();
            keyVaultClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback));
        }

        /// <summary>
        /// Retrieve the secret with the provided identifier name.
        /// </summary>
        /// <param name="keyVaultBaseUrl">The base URL to the Azure Key Vault</param>
        /// <param name="secretName">The identifier name of the secret to retrieve.</param>
        /// <returns>An <see cref="SecretBundle"/> containing the id, value and properties with this secret.</returns>
        public async Task<SecretBundle> GetSecret(string keyVaultBaseUrl, string secretName)
        {
            return await keyVaultClient.GetSecretAsync(keyVaultBaseUrl, secretName).ConfigureAwait(false);
        }
        
        /// <summary>
        /// Retrieve the value of the secret with the provided identifier name.
        /// </summary>
        /// <param name="keyVaultBaseUrl">The base URL to the Azure Key Vault</param>
        /// <param name="secretName">The identifier name of the secret to retrieve.</param>
        /// <returns>The value of the secret.</returns>
        public async Task<string> GetSecretValue(string keyVaultBaseUrl, string secretName)
        {
            SecretBundle secret = await GetSecret(keyVaultBaseUrl, secretName);

            if(secret == null)
            {
                throw new InvalidOperationException("Failed to retrieve secret!");
            }

            return secret.Value;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="keyVaultBaseUrl">The base URL to the Azure Key Vault</param>
        /// <param name="certificateName">The identifier name of the certificate to retrieve.</param>
        /// <returns>The <see cref="X509Certificate"/> from the Azure Key Vault.</returns>
        public async Task<X509Certificate> GetCertificate(string keyVaultBaseUrl, string certificateName)
        {
            var certificateBUndle = await keyVaultClient.GetCertificateAsync(keyVaultBaseUrl, certificateName);

            if(certificateBUndle == null)
            {
                throw new InvalidOperationException("Failed to retrieve certificate!");
            }

            return new X509Certificate(certificateBUndle.Cer);
        }

        /// <summary>
        /// This method fetches a token from Azure Active Directory, which can then be provided to Azure Key Vault to authenticate
        /// </summary>
        /// <param name="keyVaultBaseUrl">The base url for the keyvault.</param>
        /// <returns>The access-token.</returns>
        public async Task<string> GetAccessToken(string keyVaultBaseUrl)
        {
            var azureServiceTokenProvider = new AzureServiceTokenProvider();
            string accessToken = await azureServiceTokenProvider.GetAccessTokenAsync(keyVaultBaseUrl);
            return accessToken;
        }

        #region privates
        private static bool IsSecretActive(SecretItem theSecret)
        {
            return (theSecret.Attributes.Enabled == null || theSecret.Attributes.Enabled == true) &&
                   (theSecret.Attributes.NotBefore == null || theSecret.Attributes.NotBefore < DateTime.UtcNow) &&
                   (theSecret.Attributes.Expires == null || theSecret.Attributes.Expires > DateTime.UtcNow);
        }
        #endregion
    }
}
