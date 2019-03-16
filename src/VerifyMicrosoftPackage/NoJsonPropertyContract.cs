// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace NuGet.VerifyMicrosoftPackage
{
    /// <summary>
    /// Source: https://stackoverflow.com/a/20639697
    /// </summary>
    public class NoJsonPropertyContract : DefaultContractResolver
    {
        protected override IList<JsonProperty> CreateProperties(Type type, MemberSerialization memberSerialization)
        {
            var properties = base.CreateProperties(type, memberSerialization);

            foreach (JsonProperty property in properties)
            {
                property.PropertyName = property.UnderlyingName;
            }

            return properties;
        }
    }
}
