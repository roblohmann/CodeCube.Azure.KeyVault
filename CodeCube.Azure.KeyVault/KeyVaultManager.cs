using System;
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
        /// 
        /// </summary>
        /// <param name="keyVaultBaseUrl"></param>
        /// <param name="secretName"></param>
        /// <returns></returns>
        public async Task<SecretBundle> GetSecret(string keyVaultBaseUrl, string secretName)
        {
            return await keyVaultClient.GetSecretAsync(keyVaultBaseUrl, secretName).ConfigureAwait(false);
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
