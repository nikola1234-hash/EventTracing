using System;
using System.Diagnostics;
using System.Linq;
using System.Security.Principal;
using System.Threading;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;

namespace EventTracing
{
    class Program
    {
       

        static void Main(string[] args)
        {

            try
            {

                EventLog log = EventLog.GetEventLogs().First(o => o.Log == "Security");
                log.EnableRaisingEvents = true;
                Console.WriteLine("Listening to events...");
                log.EntryWritten += (s, e) =>
                {
                    Thread.Sleep(1000);
                    if (e.Entry.EntryType == EventLogEntryType.SuccessAudit &&
                    (e.Entry.InstanceId == 4624 || e.Entry.InstanceId == 4625 ||
                       e.Entry.InstanceId == 4672 || e.Entry.InstanceId == 4648))
                    {
                        Console.WriteLine($"Event Type: {e.Entry.EntryType}");
                        Console.WriteLine($"Instance ID: {e.Entry.InstanceId}");
                        Console.WriteLine($"Time Generated: {e.Entry.TimeGenerated}");
                        Console.WriteLine($"Source: {e.Entry.Source}");
                        Console.WriteLine($"Message: {e.Entry.Message}");

                        if (e.Entry.InstanceId == 4624 || e.Entry.InstanceId == 4625)
                        {
                            string targetUserName = e.Entry.UserName;
                            string subjectLogonId = e.Entry.ReplacementStrings[1];
                            string logonType = e.Entry.ReplacementStrings[2];
                            string workstationName = e.Entry.ReplacementStrings[13];
                            string ipAddress = e.Entry.ReplacementStrings[18];

                            Console.WriteLine($"Target User Name: {targetUserName}");
                            Console.WriteLine($"Subject Logon ID: {subjectLogonId}");
                            Console.WriteLine($"Logon Type: {logonType}");
                            Console.WriteLine($"Workstation Name: {workstationName}");
                            Console.WriteLine($"IP Address: {ipAddress}");
                        }
                        else if (e.Entry.InstanceId == 4672)
                        {
                            string accountName = e.Entry.ReplacementStrings[1];
                            string privilegeList = e.Entry.ReplacementStrings[4];

                            Console.WriteLine($"Account Name: {accountName}");
                            Console.WriteLine($"Privilege List: {privilegeList}");
                        }
                        else if (e.Entry.InstanceId == 4648)
                        {
                            string processName = e.Entry.ReplacementStrings[0];
                            string processId = e.Entry.ReplacementStrings[1];
                            string callerProcessName = e.Entry.ReplacementStrings[2];
                            string callerProcessId = e.Entry.ReplacementStrings[3];

                            Console.WriteLine($"Process Name: {processName}");
                            Console.WriteLine($"Process ID: {processId}");
                            Console.WriteLine($"Caller Process Name: {callerProcessName}");
                            Console.WriteLine($"Caller Process ID: {callerProcessId}");
                        }

                        Console.WriteLine();
                    };

            
                };
                Console.ReadLine();
            

            }
            catch (Exception ex)
            {

                Console.WriteLine(ex.Message);
                Console.ReadKey();
            }
        }
    } 
}

