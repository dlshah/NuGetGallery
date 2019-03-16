﻿// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Concurrent;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using NuGet.Frameworks;
using NuGet.Packaging;
using NuGet.Packaging.Core;
using NuGet.Versioning;
using NuGetGallery.Utilities;
using Xunit;
using Xunit.Abstractions;

namespace NuGet.VerifyMicrosoftPackage.Facts
{
    public class ProgramFacts : IDisposable
    {
        private readonly TextOutputWriter _console;
        private readonly TestDirectory _directory;

        public ProgramFacts(ITestOutputHelper output)
        {
            _console = new TextOutputWriter(output);
            _directory = TestDirectory.Create();
        }

        [Fact]
        public async Task ReturnsNegativeOneForNoArguments()
        {
            var args = new string[0];

            var exitCode = await Program.MainAsync(args, _console);

            Assert.Equal(-1, exitCode);
        }

        [Theory]
        [InlineData("-h")]
        [InlineData("--h")]
        [InlineData("-help")]
        [InlineData("--help")]
        [InlineData("/?")]
        [InlineData("/h")]
        [InlineData("/help")]
        public async Task ReturnsNegativeOneForHelp(string argument)
        {
            var args = new[] { argument };

            var exitCode = await Program.MainAsync(args, _console);

            Assert.Equal(-1, exitCode);
        }

        [Fact]
        public async Task ReturnsNegativeTwoForException()
        {
            File.WriteAllBytes(Path.Combine(_directory, "bad.nupkg"), new byte[0]);
            var args = new[] { Path.Combine(_directory, "*.nupkg") };

            var exitCode = await Program.MainAsync(args, _console);

            Assert.Equal(-2, exitCode);
            Assert.Contains("An exception occurred.", _console.Messages);
        }

        [Fact]
        public async Task ReturnsZeroForNoPackages()
        {
            var args = new[] { Path.Combine(_directory, "*.nupkg") };

            var exitCode = await Program.MainAsync(args, _console);

            Assert.Equal(0, exitCode);
            AssertCounts(valid: 0, invalid: 0);
        }

        [Fact]
        public async Task RecursiveFindsPackagesInChildDirectories()
        {
            var args = new[] { Path.Combine(_directory, "*.nupkg"), "--recursive" };
            CreatePackage(Path.Combine("inner", "testA.nupkg"));
            CreatePackage(Path.Combine("inner", "testB.nupkg"));

            var exitCode = await Program.MainAsync(args, _console);

            Assert.Equal(0, exitCode);
            AssertCounts(valid: 2, invalid: 0);
        }

        [Fact]
        public async Task ChecksMultiplePackages()
        {
            var args = new[]
            {
                Path.Combine(_directory, "inner", "testA.nupkg"),
                Path.Combine(_directory, "inner", "testB.nupkg"),
            };
            CreatePackage(Path.Combine("inner", "testA.nupkg"));
            CreatePackage(Path.Combine("inner", "testB.nupkg"));

            var exitCode = await Program.MainAsync(args, _console);

            Assert.Equal(0, exitCode);
            AssertCounts(valid: 2, invalid: 0);
        }

        [Fact]
        public async Task ContinuesAfterFailure()
        {
            var args = new[]
            {
                Path.Combine(_directory, "inner", "testA.nupkg"),
                Path.Combine(_directory, "inner", "testB.nupkg"),
            };
            CreatePackage(Path.Combine("inner", "testA.nupkg"), authors:"Not Microsoft");
            CreatePackage(Path.Combine("inner", "testB.nupkg"));

            var exitCode = await Program.MainAsync(args, _console);

            Assert.Equal(1, exitCode);
            AssertCounts(valid: 1, invalid: 1);
        }

        [Fact]
        public async Task ExitCodeIsNumberOfFailures()
        {
            var args = new[]
            {
                Path.Combine(_directory, "inner", "testA.nupkg"),
                Path.Combine(_directory, "inner", "testB.nupkg"),
                Path.Combine(_directory, "inner", "testC.nupkg"),
                Path.Combine(_directory, "inner", "testD.nupkg"),
            };
            CreatePackage(Path.Combine("inner", "testA.nupkg"), authors: "Not Microsoft");
            CreatePackage(Path.Combine("inner", "testB.nupkg"));
            CreatePackage(Path.Combine("inner", "testC.nupkg"), authors: "Not Microsoft");
            CreatePackage(Path.Combine("inner", "testD.nupkg"), authors: "Not Microsoft");

            var exitCode = await Program.MainAsync(args, _console);

            Assert.Equal(3, exitCode);
            AssertCounts(valid: 1, invalid: 3);
        }

        private void AssertCounts(int valid, int invalid)
        {
            Assert.Contains($"Valid package count: {valid}", _console.Messages);
            Assert.Contains($"Invalid package count: {invalid}", _console.Messages);
        }

        public void Dispose()
        {
            _directory.Dispose();
        }

        private void CreatePackage(
            string relativePath,
            string authors = "Microsoft",
            string copyright = "© Microsoft Corporation. All rights reserved.",
            string licenseUrl = "https://aka.ms/nugetlicense",
            string projectUrl = "https://aka.ms/nugetprj")
        {
            var fullPath = Path.Combine(_directory, relativePath);
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(fullPath)));

            var packageBuilder = new PackageBuilder();

            packageBuilder.Id = $"TestPackage-{Guid.NewGuid()}";
            packageBuilder.Version = NuGetVersion.Parse("1.0.0");
            if (authors != null)
            {
                packageBuilder.Authors.Add(authors);
            }
            packageBuilder.Copyright = copyright;
            packageBuilder.Description = "Test package.";
            packageBuilder.LicenseUrl = licenseUrl != null ? new Uri(licenseUrl) : null;
            packageBuilder.ProjectUrl = projectUrl != null ? new Uri(projectUrl) : null;
            packageBuilder.DependencyGroups.Add(new PackageDependencyGroup(
                NuGetFramework.Parse("netstandard1.0"),
                new[]
                {
                    new PackageDependency("Newtonsoft.Json", VersionRange.Parse("9.0.1")),
                }));

            using (var fileStream = File.OpenWrite(fullPath))
            {
                packageBuilder.Save(fileStream);
            }   
        }

        private class TextOutputWriter : TextWriter
        {
            private readonly ITestOutputHelper _output;

            public TextOutputWriter(ITestOutputHelper output)
            {
                _output = output;
            }

            public override Encoding Encoding => Encoding.Default;

            public ConcurrentQueue<string> Messages { get; } = new ConcurrentQueue<string>();

            public override void Write(char value)
            {
                throw new NotImplementedException();
            }

            public override void WriteLine()
            {
                WriteLine(string.Empty);
            }

            public override void WriteLine(string message)
            {
                Messages.Enqueue(message);
                _output.WriteLine(message);
            }
        }
    }
}
