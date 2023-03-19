using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.O365.Security.ETW;

namespace EventTrcing
{
    class Program
    {
        static void Main(string[] args)
        {
            // While Adminstrator is sufficent to view the Security EventLog,
            // SYSTEM is required for the Microsoft-Windows-Security-Auditing provider.
            if (!WindowsIdentity.GetCurrent().IsSystem)
            {
                Console.WriteLine("Microsoft-Windows-Security-Auditing can only be traced by SYSTEM");
                return;
            }

            // Further, only one trace session is allowed for this provider.
            // This session is created by the OS and is called 'EventLog-Security'.
            // We can't Stop this session, but we can Open a handle to it.
            var trace = new UserTrace("EventLog-Security");
            var provider = new Provider("Microsoft-Windows-Security-Auditing");

            // We also can't modify the flags of the trace session.
            // This will silently fail.
            provider.Any = Provider.AllBitsSet;

            // But we can receive events - but only those configured by the audit policy.
            // e.g. to enable event 4703 run -> auditpol /set /subcategory:"Token Right Adjusted Events"
            provider.OnEvent += (record) =>
            {
                Console.WriteLine($"Event {record.Id}({record.Name}) received.");

                if (record.Id == 4703) // "A user right was adjusted."
                {
                    var enabledPrivilegeList = record.GetUnicodeString("EnabledPrivilegeList", "");
                    var disabledPrivilegeList = record.GetUnicodeString("DisabledPrivilegeList", "");

                    Console.WriteLine($"\tEnabledPrivilegeList={enabledPrivilegeList}");
                    Console.WriteLine($"\tDisabledPrivilegeList={disabledPrivilegeList}");
                }
            };

            trace.Enable(provider);

            trace.Start();
        }
    }
}
