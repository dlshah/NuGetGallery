﻿// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Web;
using NuGet.Services.Entities;
using NuGetGallery.Security;

namespace NuGet.VerifyMicrosoftPackage
{
    public class FakeSecurityPolicyService : ISecurityPolicyService
    {
        public IEnumerable<IUserSecurityPolicySubscription> Subscriptions => throw new NotImplementedException();

        public Task<SecurityPolicyResult> EvaluateOrganizationPoliciesAsync(SecurityPolicyAction action, Organization organization, User account)
        {
            throw new NotImplementedException();
        }

        public Task<SecurityPolicyResult> EvaluatePackagePoliciesAsync(SecurityPolicyAction action, Package package, User currentUser, User owner, HttpContextBase httpContext)
        {
            throw new NotImplementedException();
        }

        public Task<SecurityPolicyResult> EvaluateUserPoliciesAsync(SecurityPolicyAction action, User user, HttpContextBase httpContext)
        {
            throw new NotImplementedException();
        }

        public bool IsSubscribed(User user, string subscriptionName)
        {
            throw new NotImplementedException();
        }

        public bool IsSubscribed(User user, IUserSecurityPolicySubscription subscription)
        {
            throw new NotImplementedException();
        }

        public Task<bool> SubscribeAsync(User user, string subscriptionName)
        {
            throw new NotImplementedException();
        }

        public Task<bool> SubscribeAsync(User user, IUserSecurityPolicySubscription subscription, bool commitChanges = true)
        {
            throw new NotImplementedException();
        }

        public Task UnsubscribeAsync(User user, string subscriptionName)
        {
            throw new NotImplementedException();
        }

        public Task UnsubscribeAsync(User user, IUserSecurityPolicySubscription subscription)
        {
            throw new NotImplementedException();
        }
    }
}
