// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
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
            return MainAsync(args, Console.Out).GetAwaiter().GetResult();
        }

        public static async Task<int> MainAsync(string[] args, TextWriter console)
        {
            _originalColor = Console.ForegroundColor;
            _console = console;

            try
            {
                return await RunAsync(args.ToList());
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

        private static async Task<int> RunAsync(List<string> args)
        {
            // Evaluate command line options.
            if (args.Count < 1
                || (new[] { "-h", "--h", "-help", "--help", "/?", "/h", "/help" }).Any(x => HasOption(args, x)))
            {
                _console.WriteLine("There must be at least one command line argument.");
                _console.WriteLine();
                _console.WriteLine("Each argument is expected to be a file path to a package (.nupkg).");
                _console.WriteLine();
                _console.WriteLine("Relative paths and wildcards in the file name are supported.");
                _console.WriteLine();
                _console.WriteLine("Globbing and wildcards in the directory are not supported.");
                _console.WriteLine();
                _console.WriteLine("Use --recursive to apply a wildcard recursively.");

                return -1;
            }

            var recursive = HasOption(args, "--recursive");

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
            foreach (var arg in args)
            {
                if (string.IsNullOrWhiteSpace(arg))
                {
                    continue;
                }

                _console.WriteLine("Using the following package path argument:");
                _console.WriteLine(arg);
                _console.WriteLine();

                var directory = Path.GetDirectoryName(arg);
                if (string.IsNullOrEmpty(directory))
                {
                    directory = ".";
                }

                var fileName = Path.GetFileName(arg);

                IEnumerable<string> paths;
                if (fileName.Contains("*"))
                {
                    paths = Directory.EnumerateFiles(
                        directory,
                        fileName,
                        recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly);
                }
                else
                {
                    paths = new[] { arg };
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

        private static bool HasOption(List<string> args, string option)
        {
            var count = args.RemoveAll(x => string.Equals(x, option, StringComparison.OrdinalIgnoreCase));
            return count > 0;
        }
    }
}
