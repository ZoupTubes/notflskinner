using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace flskinner
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            Bootstrap.Setup();

            foreach (var arg in Environment.GetCommandLineArgs())
            {
                if (arg == "-nogui")
                {
                    Core.inject(Config.current.flStudioPath, Config.current.flStudioPath + @"\FL64.exe");
                    Environment.Exit(0);
                }
            }

            InitializeComponent();

            Version.Content = Core.Version;

            flStudioPath.Content = Config.current.flStudioPath;

            int selectedIndex = -1;

            SkinsList.ItemsSource = Skin.skins;
            SkinsList.SelectedIndex = selectedIndex;

            UpdateSkinLabel();

            setMixerColors.IsChecked = Config.current.setMixerColors;
            setGridColors.IsChecked = Config.current.setGridColors;
            setDefaultPatternColor.IsChecked = Config.current.setDefaultPatternColor;
            setPlaylistTrackColors.IsChecked = Config.current.setPlaylistTrackColors;
        }

        private void UpdateSkinLabel()
        {
            foreach (Skin s in Skin.skins)
            {
                if (s.fileName == Config.current.currentSkin)
                {
                    currentSkin.Content = s.name;

                    break;
                }
            }
        }

        private void LaunchFL_Click(object sender, RoutedEventArgs e)
        {
            Core.inject(Config.current.flStudioPath, Config.current.flStudioPath + @"\FL64.exe");
        }

        private void OpenSkinsFolder_Click(object sender, RoutedEventArgs e)
        {
            Process.Start("explorer.exe", Skin.GetSkinsFolder());
        }

        private void SkinsList_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (e.AddedItems[0] != null)
            {
                Config.current.currentSkin = ((Skin)e.AddedItems[0]).fileName;
                Config.current.Save();

                UpdateSkinLabel();
            }
        }

        private void ChangeFLFolder_Click(object sender, RoutedEventArgs e)
        {
            Bootstrap.PickFLFolder();
            flStudioPath.Content = Config.current.flStudioPath;
        }

        private void OpenConfigFolder_Click(object sender, RoutedEventArgs e)
        {
            var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var folderPath = string.Format(@"{0}\flskinner\", appDataPath);
            Process.Start("explorer.exe", folderPath);
        }

        private void setMixerColors_Click(object sender, RoutedEventArgs e)
        {
            Config.current.setMixerColors = ((CheckBox)sender).IsChecked.Value;
            Config.current.Save();
        }

        private void setGridColorsFromSkin_Click(object sender, RoutedEventArgs e)
        {
            Config.current.setGridColors = ((CheckBox)sender).IsChecked.Value;
            Config.current.Save();
        }

        private void setDefaultPatternColorFromSkin_Click(object sender, RoutedEventArgs e)
        {
            Config.current.setDefaultPatternColor = ((CheckBox)sender).IsChecked.Value;
            Config.current.Save();
        }

        private void setPlaylistTrackColorsFromSkin_Click(object sender, RoutedEventArgs e)
        {
            Config.current.setPlaylistTrackColors = ((CheckBox)sender).IsChecked.Value;
            Config.current.Save();
        }

        private void CreateShortcut(object sender, RoutedEventArgs e)
        {
            var desktopFolder = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            var lnkName = "FL Studio (skinned)";

            string lnkPath = System.IO.Path.Combine(desktopFolder, lnkName) + ".lnk";
            System.IO.File.WriteAllBytes(lnkPath, new byte[] { });

            Shell32.Shell shl = new Shell32.ShellClass();
            Shell32.Folder dir = shl.NameSpace(desktopFolder);
            Shell32.FolderItem itm = dir.Items().Item(lnkName + ".lnk");
            Shell32.ShellLinkObject lnk = (Shell32.ShellLinkObject)itm.GetLink;


            lnk.Path = System.Reflection.Assembly.GetExecutingAssembly().Location;
            lnk.Arguments = "-nogui";
            lnk.WorkingDirectory = System.IO.Path.GetDirectoryName(lnk.Path);
            lnk.SetIconLocation(string.Format(@"{0}\FL64.exe", Config.current.flStudioPath), 0);

            lnk.Save(lnkPath);
        }
    }
}
