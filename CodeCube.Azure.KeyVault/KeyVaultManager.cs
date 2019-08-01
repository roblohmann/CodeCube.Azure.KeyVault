using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Rest.Azure;

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

        #region secrets
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
            SecretBundle secret = await GetSecret(keyVaultBaseUrl, secretName).ConfigureAwait(false);

            if (secret == null)
            {
                throw new InvalidOperationException("Failed to retrieve secret!");
            }

            return secret.Value;
        }

        /// <summary>
        /// Retrieve a list of all active values matching the provided secretname.
        /// </summary>
        /// <param name="keyVaultBaseUrl">The base URL to the Azure Key Vault</param>
        /// <param name="secretName">The identifier name of the secret to retrieve.</param>
        /// <returns>A list of <see cref="SecretValue"/> containg all currently active values matching the provided secretname.</returns>
        public async Task<List<SecretValue>> GetActiveSecretValues(string keyVaultBaseUrl, string secretName)
        {
            IPage<SecretItem> secrets = await keyVaultClient.GetSecretVersionsAsync(keyVaultBaseUrl, secretName);
            List<SecretValue> activeSecrets = new List<SecretValue>();

            if (secrets == null || !secrets.Any())
            {
                return activeSecrets;
            }

            foreach (var secret in secrets)
            {
                if (IsSecretActive(secret))
                {
                    var secretBundle = await keyVaultClient.GetSecretAsync(keyVaultBaseUrl, secretName, secret.Identifier.Version)
                                        .ConfigureAwait(false);

                    activeSecrets.Add(new SecretValue(secretBundle.Value));
                }
            }

            return activeSecrets;
        }
        #endregion

        #region certificates
        /// <summary>
        /// 
        /// </summary>
        /// <param name="keyVaultBaseUrl">The base URL to the Azure Key Vault</param>
        /// <param name="certificateName">The identifier name of the certificate to retrieve.</param>
        /// <returns>The <see cref="X509Certificate"/> from the Azure Key Vault.</returns>
        public async Task<X509Certificate> GetCertificate(string keyVaultBaseUrl, string certificateName)
        {
            var certificateBUndle = await keyVaultClient.GetCertificateAsync(keyVaultBaseUrl, certificateName)
                                    .ConfigureAwait(false);

            if (certificateBUndle == null)
            {
                throw new InvalidOperationException("Failed to retrieve certificate!");
            }

            return new X509Certificate(certificateBUndle.Cer);
        }
        #endregion

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
