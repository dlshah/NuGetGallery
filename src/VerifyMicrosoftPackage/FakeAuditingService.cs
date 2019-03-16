using System;
using System.Threading.Tasks;
using NuGetGallery.Auditing;

namespace NuGet.VerifyMicrosoftPackage
{
    public class FakeAuditingService : IAuditingService
    {
        public Task SaveAuditRecordAsync(AuditRecord record)
        {
            throw new NotImplementedException();
        }
    }
}
