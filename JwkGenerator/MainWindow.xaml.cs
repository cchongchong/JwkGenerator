using Microsoft.Win32;
using Newtonsoft.Json;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Windows;

namespace JwkGenerator
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void btnOpenFile_Click(object sender, RoutedEventArgs e)
        {
            var openFileDialog = new OpenFileDialog();
            openFileDialog.Filter = "Certificate files (*.cer, *.pfx)|*.cer;*.pfx";
            if (openFileDialog.ShowDialog() == true)
            {
                try
                {
                    var cert = new X509Certificate2(openFileDialog.FileName, txtPassword.Text, X509KeyStorageFlags.Exportable);
                    var jwk = new JsonWebKeyDto(cert);
                    txtResult.Text = JsonConvert.SerializeObject(jwk, Formatting.Indented);
                }
                catch (Exception exception)
                {
                    txtResult.Text = exception.ToString();
                }
            }
        }
    }

    public static class Base64Url
    {
        public static string Encode(byte[] arg)
        {
            string s = Convert.ToBase64String(arg); // Standard base64 encoder

            s = s.Split('=')[0]; // Remove any trailing '='s
            s = s.Replace('+', '-'); // 62nd char of encoding
            s = s.Replace('/', '_'); // 63rd char of encoding

            return s;
        }

        public static byte[] Decode(string arg)
        {
            string s = arg;
            s = s.Replace('-', '+'); // 62nd char of encoding
            s = s.Replace('_', '/'); // 63rd char of encoding

            switch (s.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 2: s += "=="; break; // Two pad chars
                case 3: s += "="; break; // One pad char
                default: throw new Exception("Illegal base64url string!");
            }

            return Convert.FromBase64String(s); // Standard base64 decoder
        }
    }
}
