namespace MalPacker.Packing;

using System.Security.Cryptography;

public sealed class SectionEncryptor
{
    public byte[] EncryptSection(byte[] sectionData, out byte[] key)
    {
        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.GenerateKey();
        aes.GenerateIV();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        key = new byte[aes.Key.Length + aes.IV.Length];
        Buffer.BlockCopy(aes.Key, 0, key, 0, aes.Key.Length);
        Buffer.BlockCopy(aes.IV, 0, key, aes.Key.Length, aes.IV.Length);

        using var encryptor = aes.CreateEncryptor();
        return encryptor.TransformFinalBlock(sectionData, 0, sectionData.Length);
    }

    public byte[] DecryptSection(byte[] encryptedData, byte[] key)
    {
        using var aes = Aes.Create();
        aes.Key = key[..32];
        aes.IV = key[32..48];
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using var decryptor = aes.CreateDecryptor();
        return decryptor.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
    }
}
