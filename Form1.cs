using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace YanoDeobfuscator
{
    public partial class Form1 : Form
    {

        #region Declarations
        public string DirectoryName = "";
        public int ConstantKey;
        public int ConstantNum;
        public MethodDef Methoddecryption;
        public TypeDef Typedecryption;
        public MethodDef MethodeResource;
        public TypeDef TypeResource;
        public ModuleDefMD module;
        public int x;
        public int DeobedStringNumber;

        #endregion

        #region Designer

        public Form1()
        {
            InitializeComponent();
        }

        private void button3_Click(object sender, EventArgs e)
        {
            System.Environment.Exit(0);
        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }

        private void TextBox1DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                e.Effect = DragDropEffects.Copy;
            }
            else
            {
                e.Effect = DragDropEffects.None;
            }
        }

        private void TextBox1DragDrop(object sender, DragEventArgs e)
        {
            try
            {
                Array array = (Array) e.Data.GetData(DataFormats.FileDrop);
                if (array != null)
                {
                    string text = array.GetValue(0).ToString();
                    int num = text.LastIndexOf(".", StringComparison.Ordinal);
                    if (num != -1)
                    {
                        string text2 = text.Substring(num);
                        text2 = text2.ToLower();
                        if (text2 == ".exe" || text2 == ".dll")
                        {
                            Activate();
                            textBox1.Text = text;
                            int num2 = text.LastIndexOf("\\", StringComparison.Ordinal);
                            if (num2 != -1)
                            {
                                DirectoryName = text.Remove(num2, text.Length - num2);
                            }
                            if (DirectoryName.Length == 2)
                            {
                                DirectoryName += "\\";
                            }
                        }
                    }
                }
            }
            catch
            {
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            module = ModuleDefMD.Load(textBox1.Text);
            FindStringDecrypterMethods(module);
            if (Methoddecryption == null)
            {
                FindStringDecrypterMethodsWithflow(module);
                x = 1;
            }
            DecryptStringsInMethod(module, Methoddecryption);
            string text2 = Path.GetDirectoryName(textBox1.Text);
            if (!text2.EndsWith("\\"))
            {
                text2 += "\\";
            }
            string path = text2 + Path.GetFileNameWithoutExtension(textBox1.Text) + "_patched" +
                          Path.GetExtension(textBox1.Text);
            module.Write(path);
            label2.Text = "Successfully decrypted " + DeobedStringNumber + " strings !";
        }

        #endregion

        #region Method

        private void FindStringDecrypterMethods(ModuleDefMD module)
        {
            foreach (var type in module.Types)
            {
                foreach (var method in type.Methods)
                {
                    if (method.HasBody == false)
                        continue;
                    if (method.Body.HasInstructions)
                    {
                        var instrs = method.Body.Instructions;
                        if (instrs.Count > 52)
                        {
                            for (int i = 0; i < instrs.Count - 3; i++)
                            {
                                if (instrs[i].IsLdcI4() && instrs[1].OpCode.Code == Code.Ldarg_1 &&
                                    instrs[2].OpCode.Code == Code.Add && instrs[3].OpCode.Code == Code.Stloc_0 &&
                                    instrs[4].OpCode.Code == Code.Ldarg_0 && instrs[42].OpCode.Code == Code.Or &&
                                    instrs[50].OpCode.Code == Code.Ldloc_1)
                                {
                                    Methoddecryption = method;
                                    Typedecryption = type;
                                    ConstantKey = instrs[i].GetLdcI4Value();
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        private void FindStringDecrypterMethodsWithflow(ModuleDefMD module)
        {
            foreach (var type in module.Types)
            {
                foreach (var method in type.Methods)
                {
                    if (method.HasBody == false)
                        continue;
                    if (method.Body.HasInstructions)
                    {
                        var instrs = method.Body.Instructions;
                        if (instrs.Count > 52)
                        {
                            for (int i = 0; i < instrs.Count - 3; i++)
                            {
                                if (instrs[i].IsLdcI4() && instrs[1].OpCode.Code == Code.Ldarg_1 &&
                                    instrs[2].OpCode.Code == Code.Add && instrs[3].OpCode.Code == Code.Stloc_0 &&
                                    instrs[4].OpCode.Code == Code.Ldc_I4_0 && instrs[42].OpCode.Code == Code.Ldloc_0 &&
                                    instrs[45].OpCode.Code == Code.Add && instrs[56].OpCode.Code == Code.Add)
                                {
                                    Methoddecryption = method;
                                    Typedecryption = type;
                                    ConstantKey = instrs[i].GetLdcI4Value();
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        private void DecryptStringsInMethod(ModuleDefMD module, MethodDef Methoddecryption)
        {
            foreach (TypeDef type in module.Types)
            {
                foreach (MethodDef method in type.Methods)
                {
                    if (!method.HasBody)
                        break;
                    for (int i = 0; i < method.Body.Instructions.Count; i++)
                    {
                        if (method.Body.Instructions[i].OpCode == OpCodes.Ldstr)
                        {
                            if (method.Body.Instructions[i + 1].IsLdcI4())
                                ConstantNum = (method.Body.Instructions[i + 1].GetLdcI4Value());
                            if (method.Body.Instructions[i + 2].Operand.ToString().Contains(Methoddecryption.ToString()))
                            {
                                CilBody body = method.Body;
                                var string2decrypt = method.Body.Instructions[i].Operand.ToString();
                                string decryptedstring = null;

                                Assembly assembly = Assembly.LoadFile(textBox1.Text);
                                Type typez = assembly.GetType(Typedecryption.Name);
                                if (typez != null)
                                {
                                    MethodInfo methodInfo = typez.GetMethod(Methoddecryption.Name,
                                        BindingFlags.InvokeMethod | BindingFlags.NonPublic | BindingFlags.Static);
                                    if (methodInfo != null)
                                    {
                                        object result = null;
                                        ParameterInfo[] parameters = methodInfo.GetParameters();
                                        if (parameters.Length == 0)
                                        {

                                        }
                                        else
                                        {
                                            object[] parametersArray = new object[] {string2decrypt, ConstantNum};

                                            result = methodInfo.Invoke(methodInfo, parametersArray);
                                            decryptedstring = result.ToString();
                                            DeobedStringNumber = DeobedStringNumber + 1;
                                            body.Instructions[i].OpCode = OpCodes.Ldstr;
                                            body.Instructions[i].Operand = decryptedstring;
                                            body.Instructions.RemoveAt(i + 1);
                                            body.Instructions.RemoveAt(i + 1);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            label2.Text = "";
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.Title = "Browse for target assembly";
            openFileDialog.InitialDirectory = "c:\\";
            if (DirectoryName != "")
            {
                openFileDialog.InitialDirectory = this.DirectoryName;
            }
            openFileDialog.Filter = "All files (*.exe,*.dll)|*.exe;*.dll";
            openFileDialog.FilterIndex = 2;
            openFileDialog.RestoreDirectory = true;
            if (openFileDialog.ShowDialog() == DialogResult.OK)
            {
                string fileName = openFileDialog.FileName;
                textBox1.Text = fileName;
                int num = fileName.LastIndexOf("\\", StringComparison.Ordinal);
                if (num != -1)
                {
                    DirectoryName = fileName.Remove(num, fileName.Length - num);
                }
                if (DirectoryName.Length == 2)
                {
                    DirectoryName += "\\";
                }
            }

        }


    }

    #endregion



}
