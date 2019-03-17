// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.CommandLineUtils;
using Newtonsoft.Json;
using NuGet.Packaging;
using NuGet.Services.Entities;
using NuGetGallery;
using NuGetGallery.Packaging;
using NuGetGallery.Security;

namespace NuGet.VerifyMicrosoftPackage
{
    public class Program
    {
        private static ConsoleColor _originalColor;
        private static TextWriter _console;

        public static int Main(string[] args)
        {
            return Run(args, Console.Out);
        }

        public static int Run(string[] args, TextWriter console)
        {
            _originalColor = Console.ForegroundColor;
            _console = console;

            try
            {
                return Run(args);
            }
            catch (Exception ex)
            {
                OutputColor(
                    ConsoleColor.Red,
                    () =>
                    {
                        _console.WriteLine("An exception occurred.");
                        _console.WriteLine(ex);
                    });
                return -2;
            }
        }

        private static int Run(string[] args)
        {
            var app = new Application();

            app.Out = _console;
            app.Error = _console;

            app.Name = typeof(Program).Assembly.GetName().Name;

            app.Description =
                "This tool determines if a .nupkg meets the metadata requirements for Microsoft packages on" +
                Environment.NewLine +
                "nuget.org. Relative paths and wildcards in the file name are supported. Globbing and" +
                Environment.NewLine +
                "wildcards in the directory are not supported.";

            var helpOption = app.Option(
                "-? | -h | --help",
                "Show help information.",
                CommandOptionType.NoValue);

            var recursiveOption = app.Option(
                "--recursive",
                "Evaluate wildcards recursively into child directories.",
                CommandOptionType.NoValue);

            var pathsArgument = app.Argument(
                "PATHS",
                "One or more file paths to a package (.nupkg).",
                multipleValues: true);

            app.OnExecute(async () =>
            {
                if (helpOption.HasValue() || pathsArgument.Values.Count == 0)
                {
                    app.ShowHelp();
                    return -1;
                }

                // Initialize dependencies for evaluating the metadata policy.
                var packageRegistrationRepository = new FakeEntityRepository<PackageRegistration>();
                var packageRepository = new FakeEntityRepository<Package>();
                var certificateRepository = new FakeEntityRepository<Certificate>();
                var auditingService = new FakeAuditingService();
                var telemetryService = new FakeTelemetryService();
                var securityPolicyService = new FakeSecurityPolicyService();

                var packageService = new PackageService(
                    packageRegistrationRepository,
                    packageRepository,
                    certificateRepository,
                    auditingService,
                    telemetryService,
                    securityPolicyService);

                var subscription = new MicrosoftTeamSubscription();
                var policies = subscription.Policies;
                var state = RequirePackageMetadataComplianceUtility.DeserializeState(policies);

                // Iterate over each argument.
                var validCount = 0;
                var invalidCount = 0;
                foreach (var path in pathsArgument.Values)
                {
                    if (string.IsNullOrWhiteSpace(path))
                    {
                        continue;
                    }

                    _console.WriteLine("Using the following package path argument:");
                    _console.WriteLine(path);
                    _console.WriteLine();

                    var directory = Path.GetDirectoryName(path);
                    if (string.IsNullOrEmpty(directory))
                    {
                        directory = ".";
                    }

                    var fileName = Path.GetFileName(path);

                    IEnumerable<string> paths;
                    if (fileName.Contains("*"))
                    {
                        paths = Directory.EnumerateFiles(
                            directory,
                            fileName,
                            recursiveOption.HasValue() ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly);
                    }
                    else
                    {
                        paths = new[] { path };
                    }

                    foreach (var packagePath in paths)
                    {
                        if (await IsValidAsync(packageService, state, packagePath))
                        {
                            validCount++;
                        }
                        else
                        {
                            invalidCount++;
                        }
                    }
                }

                // Summarize the results.
                _console.WriteLine($"Valid package count: {validCount}");
                _console.WriteLine($"Invalid package count: {invalidCount}");

                if (invalidCount > 0)
                {
                    _console.WriteLine();
                    _console.WriteLine("The metadata validation uses the following ruleset:");
                    _console.WriteLine(JsonConvert.SerializeObject(
                        state,
                        new JsonSerializerSettings
                        {
                            ContractResolver = new NoJsonPropertyContract(),
                            Formatting = Formatting.Indented,
                        }));
                }

                return invalidCount;
            });

            try
            {
                return app.Execute(args);
            }
            catch (CommandParsingException ex)
            {
                OutputColor(
                    ConsoleColor.Red,
                    () =>
                    {
                        _console.WriteLine(ex.Message);
                    });
                app.ShowHelp();
                return -1;
            }
        }

        private static async Task<bool> IsValidAsync(
            IPackageService packageService,
            RequirePackageMetadataState state,
            string packagePath)
        {
            if (!File.Exists(packagePath) && !Directory.Exists(packagePath))
            {
                OutputColor(
                    ConsoleColor.Red,
                    () =>
                    {
                        _console.WriteLine("INVALID.");
                        _console.WriteLine(packagePath);
                        _console.WriteLine("The path does not exist.");
                    });
                return false;
            }

            if (File.GetAttributes(packagePath).HasFlag(FileAttributes.Directory))
            {
                OutputColor(
                    ConsoleColor.Red,
                    () =>
                    {
                        _console.WriteLine("INVALID.");
                        _console.WriteLine(packagePath);
                        _console.WriteLine("The path is a directory, not a file.");
                    });
                return false;
            }

            Package package;
            using (var packageStream = File.OpenRead(packagePath))
            {
                var packageArchiveReader = new PackageArchiveReader(packageStream);

                var packageStreamMetadata = new PackageStreamMetadata
                {
                    HashAlgorithm = CoreConstants.Sha512HashAlgorithmId,
                    Hash = CryptographyService.GenerateHash(
                        packageStream.AsSeekableStream(),
                        CoreConstants.Sha512HashAlgorithmId),
                    Size = packageStream.Length
                };

                var owner = new User();
                var currentUser = owner;
                var isVerified = true;

                package = await packageService.CreatePackageAsync(
                    packageArchiveReader,
                    packageStreamMetadata,
                    owner,
                    currentUser,
                    isVerified);
            }

            var isCompliant = RequirePackageMetadataComplianceUtility.IsPackageMetadataCompliant(
                package,
                state,
                out var complianceFailures);

            if (isCompliant)
            {
                OutputColor(
                    ConsoleColor.Green,
                    () =>
                    {
                        _console.WriteLine("VALID.");
                        _console.WriteLine(packagePath);
                        _console.WriteLine($"The package {package.Id} {package.Version} is compliant.");
                    });
                return true;
            }
            else
            {
                OutputColor(
                    ConsoleColor.Red,
                    () =>
                    {
                        var single = complianceFailures.Count == 1;
                        _console.WriteLine("INVALID.");
                        _console.WriteLine(packagePath);
                        _console.WriteLine($"The package {package.Id} {package.Version} is not compliant.");
                        _console.WriteLine($"There {(single ? "is" : "are")} {complianceFailures.Count} problem{(single ? string.Empty : "s")}.");
                        foreach (var failure in complianceFailures)
                        {
                            _console.WriteLine($"  - {failure}");
                        }
                    });
                return false;
            }
        }

        private static void OutputColor(ConsoleColor color, Action output)
        {
            Console.ForegroundColor = color;
            output();
            Console.ForegroundColor = _originalColor;
            _console.WriteLine();
        }
    }
}
