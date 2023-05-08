// See https://aka.ms/new-console-template for more information
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.Metrics;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.VisualBasic;
using static System.Formats.Asn1.AsnWriter;
using static System.Net.Mime.MediaTypeNames;
using static System.Net.WebRequestMethods;

Console.WriteLine("########################################################");
Console.WriteLine("###########  WELCOME TO SHARP DLL FINDER  ##############");
Console.WriteLine("########################################################");
Console.WriteLine("");
Console.WriteLine("");


Console.WriteLine("~~~~~~~~~~~~~~~~~  STEP 1 OF 3: LOAD YML   ~~~~~~~~~~~~~~~~~~");
Console.WriteLine("Please key in the full path of the \"yml\" directory (download curated DLL hijacking list from https://github.com/wietze/HijackLibs");
string yml_dir = Console.In.ReadLine();
yml_dir = yml_dir.TrimEnd('\\');
//string yml_dir = "c:\\users\\public\\yml";

if (!Directory.Exists(yml_dir))
{
    Console.WriteLine("{0} is not a valid directory.", yml_dir);
    Environment.Exit(0);
}


string[] allfiles = Directory.GetFiles(yml_dir, "*.*", SearchOption.AllDirectories);
string[] allpaths = (string[])allfiles.Clone();
int counter = 0;
//trim the paths
foreach (String path in allpaths)
{
    allpaths[counter] = path.Substring(0,path.LastIndexOf("\\"));
    counter++;
        
}
string[] distinctpaths = allpaths.Distinct().ToArray();
Console.WriteLine("Total categories count: {0}", distinctpaths.Length);
Console.WriteLine("Total file count: {0}", allfiles.Length);

counter = 1;
Console.WriteLine("~~~~~~~~  STEP 2 OF 3: SPECIFY CATEGORY TO SEARCH   ~~~~~~~~~");
foreach (String path in distinctpaths)
{
    Console.WriteLine("{0}) {1} >",
        counter,
        path);
    counter++;
}
int category = int.Parse(Console.In.ReadLine());
category--;

Console.WriteLine("Extracting yml files from category <{0}> ....", distinctpaths[category]);


string[] allymlfiles = Directory.GetFiles(distinctpaths[category], "*.yml", SearchOption.TopDirectoryOnly);

Console.WriteLine("The program will now check for {0} possible dll hijacks. Press any key to continue ... ", allymlfiles.Length);
Console.ReadKey();

var searchorderlist = new List<Tuple<string, string, string>>();
var sideloadinglist = new List<Tuple<string, string>>();
var phantomlist = new List<Tuple<string, string, string>>();
var environmentvarlist = new List<Tuple<string, string, string>>();

foreach (string ymlfilename in allymlfiles)
{
    // Parse each yml file and test if executables mentioned in the yml file exist in local environment. if exist, write into tuple
    string[] lines = System.IO.File.ReadAllLines(@ymlfilename, Encoding.UTF8);
    counter = 0;
    string dllname = "";
    foreach (string line in lines)
    {
        if (line.Contains("Name")) 
        {
            dllname = line.Substring(6);
        }

        int offsetvar = 0;
        int offsetvar2 = 0;
        string executablefilename = "";
        string executablefilepath = "";
        string envvar = "";
        string conditionvar = "";
        string[] executablefiles;
        
        switch (line.Trim())
        {

            case "Type: Sideloading":
                
                offsetvar = counter - 1;
                while (!(lines[offsetvar].Contains("Path:")))
                {
                    offsetvar--;
                }
                executablefilename = (lines[offsetvar].Trim().Substring(lines[offsetvar].Trim().LastIndexOf("\\") + 1)).Trim('\'');
                try { executablefilepath = (lines[offsetvar].Trim().Substring(0, lines[offsetvar].Trim().LastIndexOf("\\"))).Trim('\'').Substring(9); }
                catch { executablefilepath = ""; }
                Console.Write("Checking executable for <{0}> --> <{1}> --> <{2}>  ...  ", dllname, executablefilepath, executablefilename);

                try
                {
                    executablefiles = Directory.GetFiles(GetSystemPath(executablefilepath), executablefilename, SearchOption.TopDirectoryOnly);

                    if (executablefiles.Length > 0)
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.Write("[FOUND]!");
                        Console.ForegroundColor = ConsoleColor.White;
                        Console.WriteLine("");
                        sideloadinglist.Add(Tuple.Create(dllname, GetSystemPath(executablefilepath) + executablefilename));
                    }
                    else {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("[FAILED]");
                        Console.ForegroundColor = ConsoleColor.White;
                    }
                    
                
                }
                catch (Exception e) { }
                break;
            case "Type: Environment Variable":
                offsetvar = counter - 1;
                while (!(lines[offsetvar].Contains("Path:")))
                {
                    offsetvar--;
                }
                executablefilename = (lines[offsetvar].Trim().Substring(lines[offsetvar].Trim().LastIndexOf("\\") + 1)).Trim('\'');

                try { executablefilepath = (lines[offsetvar].Trim().Substring(0, lines[offsetvar].Trim().LastIndexOf("\\"))).Trim('\'').Substring(9); }
                catch { executablefilepath = ""; }
                Console.Write("Checking executable for <{0}> --> <{1}> --> <{2}>  ...  ", dllname, executablefilepath, executablefilename);
                try
                {
                    executablefiles = Directory.GetFiles(GetSystemPath(executablefilepath), executablefilename, SearchOption.TopDirectoryOnly);
                    if (executablefiles.Length > 0)
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.Write("[FOUND!]");
                        Console.ForegroundColor = ConsoleColor.White;
                        Console.WriteLine("");

                        // extracting the environment variable from the yml file
                        offsetvar2 = counter + 1;
                        while (!(lines[offsetvar2].Contains("Variable:")))
                        {
                            offsetvar2++;
                            if (offsetvar2 > counter + 2) {
                                offsetvar2 = counter;
                                break; }
                        }
                        
                        if (offsetvar2 == counter) {
                            offsetvar2 = counter - 1;
                            while (!(lines[offsetvar2].Contains("Variable:")))
                            {
                                offsetvar2--;
                                if (offsetvar2 > counter - 2)
                                {
                                    offsetvar2 = counter;
                                    break;
                                }
                            }
                        }
                        envvar = "null";
                        if (offsetvar2 != counter)
                            envvar = lines[offsetvar2].Trim().Substring(10);


                        environmentvarlist.Add(new Tuple<string, string, string>(dllname, GetSystemPath(executablefilepath) + executablefilename, envvar));
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("[FAILED]");
                        Console.ForegroundColor = ConsoleColor.White;
                    }
                }
                catch (Exception e) { }

                
                break;
            case "Type: Search Order":
                offsetvar = counter - 1;
                while (!(lines[offsetvar].Contains("Path:")))
                {
                    offsetvar--;
                }
                executablefilename = (lines[offsetvar].Trim().Substring(lines[offsetvar].Trim().LastIndexOf("\\") + 1)).Trim('\'');

                try { executablefilepath = (lines[offsetvar].Trim().Substring(0, lines[offsetvar].Trim().LastIndexOf("\\"))).Trim('\'').Substring(9); }
                catch { executablefilepath = ""; }
                
                Console.Write("Checking executable for <{0}> --> <{1}> --> <{2}>  ...  ", dllname, executablefilepath, executablefilename);
                try
                {
                    executablefiles = Directory.GetFiles(GetSystemPath(executablefilepath), executablefilename, SearchOption.TopDirectoryOnly);
                    if (executablefiles.Length > 0)
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.Write("[FOUND!]");
                        Console.ForegroundColor = ConsoleColor.White;
                        Console.WriteLine("");

                        // extracting the condition (if any) from the yml file
                        offsetvar2 = counter + 1;
                        while (!(lines[offsetvar2].Contains("Condition:")))
                        {
                            offsetvar2++;
                            if (offsetvar2 > counter + 2)
                            {
                                offsetvar2 = counter;
                                break;
                            }
                        }

                        if (offsetvar2 == counter)
                        {
                            offsetvar2 = counter - 1;
                            while (!(lines[offsetvar2].Contains("Condition:")))
                            {
                                offsetvar2--;
                                if (offsetvar2 > counter - 2)
                                {
                                    offsetvar2 = counter;
                                    break;
                                }
                            }
                        }
                        conditionvar = "null";
                        if (offsetvar2 != counter)
                            conditionvar = lines[offsetvar2].Trim().Substring(11);



                        searchorderlist.Add(new Tuple<string, string, string>(dllname, GetSystemPath(executablefilepath) + executablefilename,conditionvar));
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("[FAILED]");
                        Console.ForegroundColor = ConsoleColor.White;
                    }
                }
                catch (Exception e) { }
                
                break;
            case "Type: Phantom":
                offsetvar = counter - 1;
                while (!(lines[offsetvar].Contains("Path:")))
                {
                    offsetvar--;
                }
                executablefilename = (lines[offsetvar].Trim().Substring(lines[offsetvar].Trim().LastIndexOf("\\") + 1)).Trim('\'');

                try { executablefilepath = (lines[offsetvar].Trim().Substring(0, lines[offsetvar].Trim().LastIndexOf("\\"))).Trim('\'').Substring(9); }
                catch { executablefilepath = ""; }
                Console.Write("Checking executable for <{0}> --> <{1}> --> <{2}>  ...  ", dllname, executablefilepath, executablefilename);
                try
                {
                    executablefiles = Directory.GetFiles(GetSystemPath(executablefilepath), executablefilename, SearchOption.TopDirectoryOnly);
                    if (executablefiles.Length > 0)
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.Write("[FOUND!]");
                        Console.ForegroundColor = ConsoleColor.White;
                        Console.WriteLine("");

                        // extracting the condition (if any) from the yml file
                        offsetvar2 = counter + 1;
                        while (!(lines[offsetvar2].Contains("Condition:")))
                        {
                            offsetvar2++;
                            if (offsetvar2 > counter + 2)
                            {
                                offsetvar2 = counter;
                                break;
                            }
                        }

                        if (offsetvar2 == counter)
                        {
                            offsetvar2 = counter - 1;
                            while (!(lines[offsetvar2].Contains("Condition:")))
                            {
                                offsetvar2--;
                                if (offsetvar2 > counter - 2)
                                {
                                    offsetvar2 = counter;
                                    break;
                                }
                            }
                        }
                        conditionvar = "null";
                        if (offsetvar2 != counter)
                            conditionvar = lines[offsetvar2].Trim().Substring(11);

                        phantomlist.Add(new Tuple<string, string, string>(dllname, GetSystemPath(executablefilepath) + executablefilename, conditionvar));
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("[FAILED]");
                        Console.ForegroundColor = ConsoleColor.White;
                    }
                }
                catch (Exception e) { }
                
                break;

        }
        

        counter++;
    }

    
}


Console.WriteLine("~~~~~~~~~~~~~~~~~  STEP 3 OF 3: WRITE OUTPUT TO FILE   ~~~~~~~~~~~~~~~~~~");
Console.Write("Please key in the directory you want to save the output file to ... : ");
string output_dir = Console.In.ReadLine();
output_dir = output_dir.TrimEnd('\\');

if (!Directory.Exists(output_dir))
{
    Console.WriteLine("{0} is not a valid directory.", output_dir);
    Environment.Exit(0);
}
Console.WriteLine("");


Console.WriteLine("########################################################");
Console.WriteLine("#######  LIST OF POSSIBLE SIDELOADING HIJACKS  #########");
Console.WriteLine("########################################################");

if (Directory.Exists(Path.GetDirectoryName(output_dir + "\\output.txt")))
{
    System.IO.File.Delete(output_dir + "\\output.txt");
}


using StreamWriter outputfile = new(output_dir+"\\output.txt", append: true);


Console.WriteLine("### START OF SIDE LOADING POSSIBLE HIJACK LIST - FORMAT (dllname, binary file)");
await outputfile.WriteLineAsync("### START OF SIDE LOADING POSSIBLE HIJACK LIST - FORMAT (dllname, binary file)");

foreach (var arg in sideloadinglist)
{
    Console.WriteLine("({0},{1})",arg.Item1, arg.Item2);
    await outputfile.WriteLineAsync("(" + arg.Item1 + "," + arg.Item2 + ")");
}


Console.WriteLine("### END OF SIDE LOADING POSSIBLE HIJACK LIST - FORMAT (dllname, binary file)");
await outputfile.WriteLineAsync("### END OF SIDE LOADING POSSIBLE HIJACK LIST - FORMAT (dllname, binary file)");
await outputfile.WriteLineAsync("");
await outputfile.WriteLineAsync("");

Console.WriteLine("");
Console.WriteLine("");


Console.WriteLine("### START OF ENV VAR POSSIBLE HIJACK LIST - FORMAT (dllname, binary file, env var name)");
await outputfile.WriteLineAsync("### START OF ENV VAR POSSIBLE HIJACK LIST - FORMAT (dllname, binary file, env var name)");

foreach (var arg in environmentvarlist)
{
    Console.WriteLine("({0},{1})", arg.Item1, arg.Item2);
    await outputfile.WriteLineAsync("(" + arg.Item1 + "," + arg.Item2 + "," + arg.Item3 + ")");
}


Console.WriteLine("### END OF ENV VAR POSSIBLE HIJACK LIST - FORMAT (dllname, binary file, env var name)");
await outputfile.WriteLineAsync("### END OF ENV VAR POSSIBLE HIJACK LIST - FORMAT (dllname, binary file, env var name)");
await outputfile.WriteLineAsync("");
await outputfile.WriteLineAsync("");

Console.WriteLine("");
Console.WriteLine("");


Console.WriteLine("### START OF SEARCH ORDER POSSIBLE HIJACK LIST - FORMAT (dllname, binary file, condition if any)");
await outputfile.WriteLineAsync("### START OF SEARCH ORDER POSSIBLE HIJACK LIST - FORMAT (dllname, binary file, condition if any)");

foreach (var arg in searchorderlist)
{
    Console.WriteLine("({0},{1})", arg.Item1, arg.Item2);
    await outputfile.WriteLineAsync("(" + arg.Item1 + "," + arg.Item2 + "," + arg.Item3 + ")");
}


Console.WriteLine("### END OF SEARCH ORDER POSSIBLE HIJACK LIST - FORMAT (dllname, binary file, condition if any)");
await outputfile.WriteLineAsync("### END OF SEARCH ORDER POSSIBLE HIJACK LIST - FORMAT (dllname, binary file, condition if any)");
await outputfile.WriteLineAsync("");
await outputfile.WriteLineAsync("");


Console.WriteLine("");
Console.WriteLine("");



Console.WriteLine("### START OF PHANTOM POSSIBLE HIJACK LIST - FORMAT (dllname, binary file, condition if any)");
await outputfile.WriteLineAsync("### START OF PHANTOM POSSIBLE HIJACK LIST - FORMAT (dllname, binary file, condition if any)");

foreach (var arg in phantomlist)
{
    Console.WriteLine("({0},{1})", arg.Item1, arg.Item2);
    await outputfile.WriteLineAsync("(" + arg.Item1 + "," + arg.Item2 + "," + arg.Item3 + ")");
}



Console.WriteLine("### END OF PHANTOM POSSIBLE HIJACK LIST - FORMAT (dllname, binary file, condition if any)");
await outputfile.WriteLineAsync("### END OF PHANTOM POSSIBLE HIJACK LIST - FORMAT (dllname, binary file, condition if any)");

Console.WriteLine("");
Console.WriteLine("");

Console.ForegroundColor = ConsoleColor.Green;
Console.WriteLine("File written successfully ({0}\\output.txt).",output_dir);
Console.WriteLine("Program executed successfuly. Press any key to quit ...");



string GetSystemPath(String syspath)
{
    string pathval;
    switch (syspath)
    {
        case "%SYSTEM32%":
            pathval = "C:\\Windows\\System32\\";
            break;
        case "%SYSWOW64%":
            pathval = "C:\\Windows\\SysWOW64\\";
            break;
        case "%SWINDIR%":
            pathval = "C:\\Windows\\";
            break;
        case "%PROGRAMFILES%":
            pathval = "C:\\Program Files (x86)\\";
            break;
        case "%PROGRAMFILES%\\Windows Kits\\10\\bin\\%VERSION%\\x86":
            pathval = "C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0.18362.0\\x86";
            break;
        case "%PROGRAMFILES%\\HTML Help Workshop":
            pathval = "C:\\Program Files (x86)\\HTML Help Workshop";
            break;
        case "%PROGRAMFILES%\\Windows Kits\\10\\bin\\%VERSION%\\x64":
            pathval = "C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0.18362.0\\x64";
            break;
        case "%PROGRAMFILES%\\Windows Kits\\10\\bin\\%VERSION%\\arm64":
            pathval = "C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0.19041.0\\arm64";
            break;
        case "%PROGRAMFILES%\\Microsoft Office\\OFFICE%VERSION%":
            pathval = "C:\\Program Files (x86)\\Microsoft Office\\Office16";
            break;
        case "%PROGRAMFILES%\\Microsoft Office\\Root\\OFFICE%VERSION%":
            pathval = "C:\\Program Files (x86)\\Microsoft Office\\Root\\Office16";
            break;
        default:
            pathval = "C:\\";
            break;

    }
    return pathval;
}

