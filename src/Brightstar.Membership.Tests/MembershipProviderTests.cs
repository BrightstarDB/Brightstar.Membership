using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web.Security;
using NUnit.Framework;

namespace Brightstar.Membership.Tests
{
    [TestFixture("type=embedded;storesDirectory=stores")]
    public class MembershipProviderTests
    {
        private readonly string _baseConnectionString;

        public MembershipProviderTests(string baseConnectionString)
        {
            _baseConnectionString = baseConnectionString;
        }

        private string GetConnectionString(string storeName)
        {
            return _baseConnectionString + ";storeName=" + storeName + "_" + DateTime.Now.Ticks;
        }

        private BrightstarMembershipProvider GetMembershipProvider(string connectionString, string applicationName = "UnitTesting")
        {
            var provider = new BrightstarMembershipProvider();
            var config = new NameValueCollection();
            config["connectionString"] = connectionString;
            config["applicationName"] = applicationName;
            provider.Initialize("BrightstarMembershipProvider", config);
            return provider;
        }

        [Test]
        public void TestUserCreation()
        {
            var provider = GetMembershipProvider(GetConnectionString("TestUserCreation"));
            MembershipCreateStatus status;
            var user = provider.CreateUser("alpha", "password", "alpha@example.com", "To Be Or Not To Be?", "That is the Question",
                true, null, out status);
            Assert.That(status, Is.EqualTo(MembershipCreateStatus.Success));
            Assert.That(user, Is.Not.Null);

            user = provider.GetUser("alpha", false);
            Assert.That(user, Is.Not.Null);
            Assert.That(user.UserName, Is.EqualTo("alpha"));
            Assert.That(user.Email, Is.EqualTo("alpha@example.com"));
            Assert.That(user.PasswordQuestion, Is.EqualTo("To Be Or Not To Be?"));
            Assert.That(user.IsApproved = true);
            Assert.That(user.IsOnline);
        }
    }
}
