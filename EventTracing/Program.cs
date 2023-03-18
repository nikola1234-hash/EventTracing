using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using System;
using System.Diagnostics.Tracing;

namespace EventTracing
{
    class Program
    {
        static void Main(string[] args)
        {

            using (var session = new TraceEventSession("MySecuritySession"))
            {
                session.EnableProvider("Microsoft-Windows-Security-Auditing", TraceEventLevel.Informational, (ulong)(EventKeywords.AuditSuccess | EventKeywords.AuditFailure));

                session.Source.Dynamic.All += data =>
                {
                    if (data.ProviderName == "Microsoft-Windows-Security-Auditing" && (data.EventName == "4624" || data.EventName == "4625" || data.EventName == "4672" || data.EventName == "4648"))
                    {
                       
                        string eventId = data.EventName;
                        string targetUserName = (string)data.PayloadValue(0);
                        string subjectLogonId = (string)data.PayloadValue(1);
                  
                        ProcessSecurityEvent(eventId, targetUserName, subjectLogonId);
                    }
                };

                Console.WriteLine("Listening for security events. Press any key to exit...");
                Console.ReadKey();
            }
        }

        static void ProcessSecurityEvent(string eventId, string targetUserName, string subjectLogonId)
        {

            Console.WriteLine($"Event ID: {eventId}");
            Console.WriteLine($"TargetUserName: {targetUserName}");
            Console.WriteLine($"SubjectLogonId: {subjectLogonId}");
        }
    }

    
 }

