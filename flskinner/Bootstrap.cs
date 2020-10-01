using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using Microsoft.Win32;
using Microsoft.WindowsAPICodePack.Dialogs;
using Newtonsoft.Json;

namespace flskinner
{
    class Bootstrap
    {
        public static void Setup()
        {
            var assembly = Assembly.GetExecutingAssembly();

            var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

            var folderPath = string.Format(@"{0}\flskinner\", appDataPath);
            var skinsFolderPath = string.Format(@"{0}\flskinner\skins\", appDataPath);

            System.IO.Directory.CreateDirectory(folderPath);

            var mainConfigPath = folderPath + "flskinner.json";
            if (!File.Exists(mainConfigPath))
            {
                var stream = assembly.GetManifestResourceStream("flskinner.Default.flskinner.json");

                using (StreamReader reader = new StreamReader(stream))
                {
                    File.WriteAllText(mainConfigPath, reader.ReadToEnd());
                }
            }

            if (!Directory.Exists(skinsFolderPath))
            {
                Directory.CreateDirectory(skinsFolderPath);

                var prefix = "flskinner.Default.skins.";

                var resourceNames = Assembly.GetExecutingAssembly()
                    .GetManifestResourceNames()
                    .Where(name => name.StartsWith(prefix));

                foreach (var name in resourceNames)
                {
                    var stream = assembly.GetManifestResourceStream(name);

                    using (StreamReader reader = new StreamReader(stream))
                    {
                        var path = string.Format("{0}{1}", skinsFolderPath, name.Replace(prefix, ""));
                        File.WriteAllText(path, reader.ReadToEnd());
                    }
                }
            }

            try
            {
                Config.current = JsonConvert.DeserializeObject<Config>(Uncommentify(File.ReadAllText(mainConfigPath)));
            }
            catch (Exception e)
            {
                StringBuilder sb = new StringBuilder();
                sb.AppendLine("An exception occured while loading the configuration file (flskinner.json in %appdata%/flskinner)");
                sb.Append(e.Message);
                MessageBox.Show(sb.ToString());
                System.Environment.Exit(1);
            }

            // some users have it in the 64 bit program files :shrug:
            if (!File.Exists(string.Format(@"{0}\FL64.exe", Config.current.flStudioPath)))
            {
                var x64Path = @"C:\Program Files\Image-Line\FL Studio 20\FL64.exe";
                if (File.Exists(x64Path))
                {
                    Config.current.flStudioPath = x64Path;
                    Config.current.Save();
                }
            }

            if (!File.Exists(string.Format(@"{0}\FL64.exe", Config.current.flStudioPath)))
            {
                PickFLFolder();
            }

            Skin.skins = new List<Skin>();

            foreach (var skinPath in Directory.GetFiles(skinsFolderPath))
            {
                try
                {
                    var skin = JsonConvert.DeserializeObject<Skin>(Uncommentify(File.ReadAllText(skinPath)));
                    skin.fileName = Path.GetFileName(skinPath);
                    Skin.skins.Add(skin);
                }
                catch (Exception e)
                {
                    StringBuilder sb = new StringBuilder();
                    sb.Append("An exception occured while loading the skin file ");
                    sb.AppendLine("'" + Path.GetFileName(skinPath) + "'");
                    sb.AppendLine("File is located under '" + Path.GetDirectoryName(skinPath) + "'");
                    sb.Append(e.Message);
                    MessageBox.Show(sb.ToString());
                }
            }
        }

        public static void PickFLFolder()
        {
            CommonOpenFileDialog dialog = new CommonOpenFileDialog();
            dialog.InitialDirectory = "C:\\";
            dialog.IsFolderPicker = false;
            dialog.Filters.Add(new CommonFileDialogFilter(@"FL64.exe", "*.exe"));
            dialog.Title = "Please select your FL64.exe";

            var res = dialog.ShowDialog();
            if (res == CommonFileDialogResult.Ok)
            {
                var path = dialog.FileName;
                if (Path.GetFileName(dialog.FileName) == "FL64.exe")
                {
                    Config.current.flStudioPath = Path.GetDirectoryName(dialog.FileName);
                    Config.current.Save();
                }
                else
                {
                    MessageBox.Show("That is not FL64.exe!");

                    PickFLFolder();
                    return;
                }
            }
            else if (res == CommonFileDialogResult.Cancel)
            {
                System.Environment.Exit(1);
            }
        }

        private static string Uncommentify(string json)
        {
            // single line comments
            json = Regex.Replace(json, @"\/\/.*", "");
            // block comments
            json = Regex.Replace(json, @"\/\*(\*(?!\/)|[^*])*\*\/", "");

            return json;
        }
    }
}
