// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Text;
using Microsoft.Extensions.CommandLineUtils;

namespace NuGet.VerifyMicrosoftPackage
{
    public class Application : CommandLineApplication
    {
        public override string GetHelpText(string commandName = null)
        {
            var sb = new StringBuilder();
            sb.AppendLine(base.GetHelpText(commandName));
            sb.AppendLine(Description);
            return sb.ToString();
        }
    }
}
