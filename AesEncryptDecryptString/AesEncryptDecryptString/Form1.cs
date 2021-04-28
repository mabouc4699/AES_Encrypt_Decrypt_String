using System;
using System.IO;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Security.Cryptography;

namespace AesEncryptDecryptString
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        //Textbox where User enters Plaintext
        private string plaintext;
        private void textBox1_TextChanged(object sender, EventArgs e)
        {
            plaintext = textBox1.Text;
        }

        //Encrypt Button Clicked
        private byte[] encrypted;
        private string decOutput;
        private void button1_Click(object sender, EventArgs e)
        {
            using (Aes myAes = Aes.Create())
            {
                //Code below allows user to select between 128, 192, and 256 bit encryption
                if (radioButton1.Checked == true)
                {
                    myAes.KeySize = 128;
                }
                else if (radioButton2.Checked == true)
                {
                    myAes.KeySize = 192;
                }
                else if (radioButton3.Checked == true)
                {
                    myAes.KeySize = 256;
                }

                //Generates encrypted output in format of bytes using instance of Aes Class (myAes)
                //Also generates decrypted output in string using myAes, saved to decOutput
                //textBox2 text is set to encrypted data (converted to string from bytes)
                encrypted = EncryptStringToBytes(plaintext, myAes.Key, myAes.IV);
                decOutput = DecryptStringFromBytes(encrypted, myAes.Key, myAes.IV);
                textBox2.Text = Convert.ToBase64String(encrypted);
            }
        }

        //Decrypt Button Clicked
        private void button2_Click(object sender, EventArgs e)
        {
            //Sets textBox3 text to decOutput (decrypted output)
            textBox3.Text = decOutput;
        }

        //When invoked, DecryptStringFromBytes returns plaintext using parameters encrypted, Key, and IV
        private string DecryptStringFromBytes(byte[] encrypted, byte[] Key, byte[] IV)
        {
            string plaintext = null;
            //Another instance of Aes class created, Key and IV properties set to passed parameters
            using (Aes classAes = Aes.Create())
            {
                classAes.Key = Key;
                classAes.IV = IV;

                //Key and IV are displayed for Educational Purposes only (must be excluded if applied to real world applications)
                textBox4.Text = Convert.ToBase64String(Key);
                textBox5.Text = Convert.ToBase64String(IV);

                //Creates ICryptoTransform Object decryptor that uses classAes attributes Key and IV
                ICryptoTransform decryptor = classAes.CreateDecryptor(classAes.Key, classAes.IV);

                //Code below uses msDecrypt (MemoryStream Object / Instance) to address encrypted byte[] array
                //A cryptostream instance (csDecrypt) takes the source (msDecrypt), decryptor object, and Mode (read)
                //A StreamReader instance (srDecrypt) takes the csDecrypt object as parameter and sets plaintext =
                //... decryption of encrypted byte[]
                using (MemoryStream msDecrypt = new MemoryStream(encrypted))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            //Returns plaintext indicated by method signature (private string...)
            return plaintext;
        }

        //When invoked, EncryptStringToBytes returns ciphertext as byte[] using parameters plaintext, Key, and IV
        private byte[] EncryptStringToBytes(string plaintext, byte[] Key, byte[] IV)
        {
            byte[] encrypted;

            using (Aes classAes = Aes.Create())
            {
                classAes.Key = Key;
                classAes.IV = IV;

                //Key and IV are displayed for Educational Purposes only (must be excluded if applied to real world applications)
                textBox4.Text = Convert.ToBase64String(Key);
                textBox5.Text = Convert.ToBase64String(IV);

                //Creates ICryptoTransform Object encryptor that uses classAes attributes Key and IV
                ICryptoTransform encryptor = classAes.CreateEncryptor(classAes.Key, classAes.IV);

                //Code below uses msEncrypt (MemoryStream Object / Instance) to address plaintext input
                //A cryptostream instance (csEncrypt) takes the source (msEncrypt), encryptor object, and Mode (write)
                //A StreamReader instance (srEncrypt) takes the csEncrypt object as parameter and sets encrypted =
                //... decryption of encrypted byte[]
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plaintext);
                        }
                        //.ToArray() used because System.IO.MemoryStream does not output to byte[]
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            //Returns byte[] array encrypted indicated by method signature (private byte[]...)
            return encrypted;
        }
    }
}
