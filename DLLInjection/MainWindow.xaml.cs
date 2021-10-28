using DummyMemory;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;
using Path = System.IO.Path;

namespace DLLInjection
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {

            //maybe remove isattached thing? dont know if a debugger could start without vs?
            if (!Memory.Admin)
            {
                Popup("Admin Required", "Please run this application in Administrative mode", PopupChoices.Ok, x =>
                {
                    Environment.Exit(0);
                });
            }

            InitializeComponent();

            window.Title += Environment.Is64BitProcess ? " - x64" : " - x86";

            ok.Click += (sender, x) => { choiceHappen?.Invoke(PopupChoices.Ok); ClosePopup(); };

            yes.Click += (sender, x) => { choiceHappen?.Invoke(PopupChoices.Yes); ClosePopup(); };

            no.Click += (sender, x) => { choiceHappen?.Invoke(PopupChoices.No); ClosePopup(); };

            cancel.Click += (sender, x) => { choiceHappen?.Invoke(PopupChoices.Cancel); ClosePopup(); };

            //init popup make sure everything is closed.
            ClosePopup();

            //get excluded procs
            RefreshProcesses(null, null);
            //dispose
            CleanupProcs(null, null);
        }


        //the process name
        public string ProcName
        {
            get
            {
                //could also be selected value?
                object item = process.SelectedItem;

                if (item == null)
                    return string.Empty;

                CustomItem custom = item as CustomItem;

                return custom.procName;
            }

        }
        private async void InjectClick(object sender, RoutedEventArgs e)
        {
            Process[] procs = Process.GetProcessesByName(ProcName);

            if (procs.Length < 1)
            {
                Popup("Zero Processes", $"'{ProcName}' is not running or could not be found", PopupChoices.Ok);
                return;
            }

            if (lv.Items.Count < 1)
            {
                Popup("Zero .dll(s)", "There is nothing to inject into the process", PopupChoices.Ok);
                return;
            }

            if (!injAll.IsChecked.Value)
            {
                procs = new Process[] { procs[0] };
            }

            for (int i = 0; i < procs.Length; i++)
            {
                Memory m = new Memory(procs[i]);
                foreach (object item in lv.Items)
                {
                    ListViewItem it = item as ListViewItem;

                    DllItem dll = it.Content as DllItem;

                    if (dll.inject)
                    {

                        Memory.InjectionStatus stat = m.Inject(dll.dll);

                        (string title, string body) status = GetStrStatus(procs[i].ProcessName, dll.dll, stat);

                        await ShowTimedPopup(status.title, status.body, TimeSpan.FromSeconds(1.5));
                    }

                }

                m = null;
                GC.Collect();
            }
        }
        private (string, string) GetStrStatus(string procName, string dllPath, Memory.InjectionStatus status)
        {
            switch (status)
            {
                case Memory.InjectionStatus.DllDoesNotExist:
                    return ("Dll Missing", "DLL does not exist");
                case Memory.InjectionStatus.NotAdmin:
                    return ("Admin Perms", "Run as ADMIN to inject");
                case Memory.InjectionStatus.BadPointer:
                case Memory.InjectionStatus.Injected:
                case Memory.InjectionStatus.CloseFail_Injected:
                    return ("Success", $"'{Path.GetFileName(dllPath)}.dll' was injected into {procName}.exe sucessfully");
                default:
                    break;
            }

            return ("Unknown", "The problem is unknown, this could mean a problem with archetype mismatch.");
        }

        //Find dll button click
        private void FindDll(object sender, RoutedEventArgs e)
        {
            OpenFileDialog file = new OpenFileDialog();
            file.Filter = "Dll Files (*.dll)|*.dll;";

            bool? dialog = file.ShowDialog(this);

            if (dialog == null)
                return;

            if (!dialog.Value)
                return;

            bool? x64 = UnmanagedDllIs64Bit(file.FileName);

            if (x64 == null)
            {
                Popup("PE Header Fail", "PE Header was not determined as x64 or x32", PopupChoices.Ok);
                return;
            }

            if (Environment.Is64BitProcess != x64.Value)
            {
                Popup("Arechetype Mismatch",
                    $"'{System.IO.Path.GetFileName(file.FileName)}' archetype does not match to injector",
                    PopupChoices.Ok);

                return;
            }

            ListViewItem item = Setup(file.FileName);

            if (item != null)
                lv.Items.Add(item);
        }

        //dlls in the listview already
        public List<string> injDlls = new List<string>();

        //create a list view item with only a dll
        private ListViewItem Setup(string dllPath)
        {
            if (injDlls.Contains(dllPath))
                return null;

            DllItem panel = new DllItem
            {
                Width = 328,
                Height = 40,
                dll = dllPath
            };

            TextBlock block = new TextBlock
            {
                Text = System.IO.Path.GetFileName(dllPath),
                Foreground = Brushes.White,
                Height = 30,
                Width = 200,
                TextWrapping = TextWrapping.Wrap,
                HorizontalAlignment = HorizontalAlignment.Left,
                VerticalAlignment = VerticalAlignment.Bottom,
                ToolTip = dllPath
            };

            Rectangle rec = new Rectangle
            {
                Width = 5
            };

            DllCheck check = new DllCheck
            {
                Content = "Inject",
                BorderBrush = Brushes.Black,
                Foreground = Brushes.White,
                Height = 18,
                VerticalAlignment = VerticalAlignment.Top,
                IsChecked = true,
                item = panel
            };

            check.Checked += ToggleLVIOn;
            check.Unchecked += ToggleLVIOff;

            Rectangle rec2 = new Rectangle
            {
                Width = 19
            };

            DllButton button = new DllButton
            {
                Content = "Remove",
                Height = 18,
                Width = 38,
                FontSize = 9.5,
                HorizontalAlignment = HorizontalAlignment.Left,
                VerticalAlignment = VerticalAlignment.Top,
                Foreground = Brushes.White,
                BorderBrush = Brushes.Black,
                Background = Brushes.Transparent,
                dllI = panel
            };

            button.Click += RemoveLVI;

            panel.Children.Add(block);
            panel.Children.Add(rec);
            panel.Children.Add(check);
            panel.Children.Add(rec2);
            panel.Children.Add(button);

            ListViewItem item = new ListViewItem()
            {
                Content = panel
            };

            button.item = item;

            injDlls.Add(dllPath);

            return item;
        }
        #region ListView Setups
        private void ToggleLVIOff(object sender, RoutedEventArgs e)
        {
            DllCheck dll = sender as DllCheck;

            dll.item.inject = false;
        }

        private void ToggleLVIOn(object sender, RoutedEventArgs e)
        {
            DllCheck dll = sender as DllCheck;

            dll.item.inject = true;
        }

        private void RemoveLVI(object sender, RoutedEventArgs e)
        {
            DllButton button = sender as DllButton;

            injDlls.Remove(button.dllI.dll);

            lv.Items.Remove(button.item);
        }
        #endregion



        #region Event
        List<string> invalidProcNames = new List<string>();
        //valid only when get for validprocs called.
        IEnumerable<Process> instan;
        IEnumerable<Process> ValidProcs
        {
            get
            {
                instan = Process.GetProcesses();
                foreach (Process p in instan)
                {
                    if (invalidProcNames.Contains(p.ProcessName))
                        continue;

                    bool has = false;
                    try
                    {
                        IntPtr x = p.Handle;
                    }
                    catch
                    {
                        invalidProcNames.Add(p.ProcessName);
                        has = true;
                    }

                    if (!has)
                    {
                        yield return p;
                    }
                }
            }
        }

        public IEnumerable<CustomItem> Items
        {
            get
            {
                bool expecting = Environment.Is64BitProcess;

                foreach (Process item in ValidProcs
                    .OrderBy(x => x.ProcessName)
                    .OrderBy(x => x.Id)
                    .OrderByDescending(x => x.MainWindowHandle != IntPtr.Zero)
                    )
                {
                    //TODO : checkbox for background procs?
                    if (IsX64(item) == expecting/* && item.MainWindowHandle != IntPtr.Zero*/)
                    {
                        yield return new CustomItem(item);
                    }
                }

            }
        }

        //grab the valid procs and then refresh the view
        private void RefreshProcesses(object sender, EventArgs e)
        {
            process.ItemsSource = Items;
            process.Items.Refresh();
        }

        //Disposes all processes
        //OnDropDownClosed
        private void CleanupProcs(object sender, EventArgs e)
        {
            if (instan == default)
                return;

            foreach (Process item in instan)
            {
                item.Dispose();
            }

        }
        #endregion

        #region Popup - Alt MessageBox.Show
        //called when a choice happens
        Action<PopupChoices> choiceHappen;

        //selected: only one delegate for this event may exist 
        void Popup(string title, string msg, PopupChoices choices, Action<PopupChoices> selected = null)
        {
            header.Text = title;
            body.Text = msg;
            popupMain.Visibility = Visibility.Visible;

            int size = 0;
            int width = (int)ok.Width;
            if (choices.HasFlag(PopupChoices.Yes))
            {
                size += width;
                yes.Visibility = Visibility.Visible;
            }

            if (choices.HasFlag(PopupChoices.No))
            {
                size += width;
                no.Visibility = Visibility.Visible;
            }

            if (choices.HasFlag(PopupChoices.Cancel))
            {
                size += width;
                cancel.Visibility = Visibility.Visible;
            }

            if (choices.HasFlag(PopupChoices.Ok))
            {
                size += width;
                ok.Visibility = Visibility.Visible;
            }

            buttonContainer.Width = size;

            choiceHappen = selected;
        }

        void ClosePopup()
        {
            popupMain.Visibility = Visibility.Collapsed;
            yes.Visibility = Visibility.Collapsed;
            no.Visibility = Visibility.Collapsed;
            ok.Visibility = Visibility.Collapsed;
            cancel.Visibility = Visibility.Collapsed;
        }

        //A timed popup 
        async Task ShowTimedPopup(string title, string msg, TimeSpan delay, Action onClose = null)
        {
            Popup(title, msg, PopupChoices.None);

            await Task.Delay(delay);

            onClose?.Invoke();
            ClosePopup();
        }
        #endregion

        #region Native / Process / dll - Checkers

        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsWow64Process([In] IntPtr hProcess, [Out] out bool lpSystemInfo);

        //determines if a process is built on the x64 archetype
        public bool IsX64(Process proc)
        {
            IsWow64Process(proc.Handle, out bool info);

            return !info;
        }
        public enum MachineType : ushort
        {
            IMAGE_FILE_MACHINE_UNKNOWN = 0x0,
            IMAGE_FILE_MACHINE_AM33 = 0x1d3,
            IMAGE_FILE_MACHINE_AMD64 = 0x8664,
            IMAGE_FILE_MACHINE_ARM = 0x1c0,
            IMAGE_FILE_MACHINE_EBC = 0xebc,
            IMAGE_FILE_MACHINE_I386 = 0x14c,
            IMAGE_FILE_MACHINE_IA64 = 0x200,
            IMAGE_FILE_MACHINE_M32R = 0x9041,
            IMAGE_FILE_MACHINE_MIPS16 = 0x266,
            IMAGE_FILE_MACHINE_MIPSFPU = 0x366,
            IMAGE_FILE_MACHINE_MIPSFPU16 = 0x466,
            IMAGE_FILE_MACHINE_POWERPC = 0x1f0,
            IMAGE_FILE_MACHINE_POWERPCFP = 0x1f1,
            IMAGE_FILE_MACHINE_R4000 = 0x166,
            IMAGE_FILE_MACHINE_SH3 = 0x1a2,
            IMAGE_FILE_MACHINE_SH3DSP = 0x1a3,
            IMAGE_FILE_MACHINE_SH4 = 0x1a6,
            IMAGE_FILE_MACHINE_SH5 = 0x1a8,
            IMAGE_FILE_MACHINE_THUMB = 0x1c2,
            IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x169,
        }

        //verify machine type, cleanup to rid of the .so file
        public static MachineType GetDllMachineType(string dllPath, bool cleanup)
        {
            FileStream fs = new FileStream(dllPath, FileMode.Open, FileAccess.Read);
            BinaryReader br = new BinaryReader(fs);
            fs.Seek(0x3c, SeekOrigin.Begin);
            Int32 peOffset = br.ReadInt32();
            fs.Seek(peOffset, SeekOrigin.Begin);
            UInt32 peHead = br.ReadUInt32();

            if (peHead != 0x00004550) // "PE\0\0", little-endian
                throw new Exception("Can't find PE header");

            MachineType machineType = (MachineType)br.ReadUInt16();
            br.Close();
            fs.Close();

            if (cleanup)
            {
                string _base = Directory.GetParent(dllPath).FullName;

                string name = System.IO.Path.GetFileName(_base);

                File.Delete(System.IO.Path.Combine(_base, name + ".so"));
            }

            return machineType;
        }

        //null when default
        public static bool? UnmanagedDllIs64Bit(string dllPath, bool cleanup = true)
        {
            switch (GetDllMachineType(dllPath, cleanup))
            {
                case MachineType.IMAGE_FILE_MACHINE_AMD64:
                case MachineType.IMAGE_FILE_MACHINE_IA64:
                    return true;
                case MachineType.IMAGE_FILE_MACHINE_I386:
                    return false;
                default:
                    return null;
            }
        }
        #endregion

       
    }

    enum PopupChoices
    {
        None,
        Ok = 100,
        Yes = 20,
        No = 10,
        Cancel = 5,
        All = Ok | Yes | No | Cancel
    }


    public class CustomItem : ComboBoxItem
    {


        public CustomItem(Process proc)
        {

            string hasUI = proc.MainWindowHandle == IntPtr.Zero ? "No" : "Yes";
            procName = proc.ProcessName;
            item = new TextBlock
            {
                FontSize = 13,

                Text = $"{proc.ProcessName} ➟ {proc.Id} ➟ UI: {hasUI}"
            };

          

            item.Padding = new Thickness(0, 0, 0, 8);
            Content = item;
        }

        public string procName;
        public TextBlock item;
    }
    public class DllItem : DockPanel
    {
        public string dll;
        public bool inject = true;
    }
    public class DllButton : Button
    {
        public ListViewItem item;
        public DllItem dllI;
    }
    public class DllCheck : CheckBox
    {
        public DllItem item;
    }

}
